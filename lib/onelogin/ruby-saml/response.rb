require "xml_security"
require "time"
require "nokogiri"
require 'onelogin/ruby-saml/attributes'

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    class Response
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      DSIG      = "http://www.w3.org/2000/09/xmldsig#"

      # TODO: This should probably be ctor initialized too... WDYT?
      attr_accessor :settings

      attr_reader :options
      attr_reader :response
      attr_reader :document

      def initialize(response, options = {})
        raise ArgumentError.new("Response cannot be nil") if response.nil?
        @options  = options
        @response = (response =~ /^</) ? response : Base64.decode64(response)
        @document = XMLSecurity::SignedDocument.new(@response)
      end

      def is_valid?
        validate
      end

      def validate!
        validate(false)
      end

      # The value of the user identifier as designated by the initialization request response
      def name_id
        @name_id ||= begin
          node = xpath_first_from_signed_assertion('/a:Subject/a:NameID')
          Utils.element_text(node)
        end
      end

      alias nameid name_id

      def sessionindex
        @sessionindex ||= begin
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
          node.nil? ? nil : node.attributes['SessionIndex']
        end
      end

      # Gets the Attributes from the AttributeStatement element.
      #
      # All attributes can be iterated over +attributes.each+ or returned as array by +attributes.all+
      # For backwards compatibility ruby-saml returns by default only the first value for a given attribute with
      #    attributes['name']
      # To get all of the attributes, use:
      #    attributes.multi('name')
      # Or turn off the compatibility:
      #    OneLogin::RubySaml::Attributes.single_value_compatibility = false
      # Now this will return an array:
      #    attributes['name']
      #
      # @return [Attributes] OneLogin::RubySaml::Attributes enumerable collection.
      #
      def attributes
        @attr_statements ||= begin
          attributes = Attributes.new

          stmt_elements = xpath_from_signed_assertion('/a:AttributeStatement')
          stmt_elements.each do |stmt_element|
            stmt_element.elements.each do |attr_element|
              name = attr_element.attributes["Name"]
              values = attr_element.elements.collect{|e|
                if (e.elements.nil? || e.elements.size == 0)
                  # SAMLCore requires that nil AttributeValues MUST contain xsi:nil XML attribute set to "true" or "1"
                  # otherwise the value is to be regarded as empty.
                  ["true", "1"].include?(e.attributes['xsi:nil']) ? nil : Utils.element_text(e)
                # explicitly support saml2:NameID with saml2:NameQualifier if supplied in attributes
                # this is useful for allowing eduPersonTargetedId to be passed as an opaque identifier to use to
                # identify the subject in an SP rather than email or other less opaque attributes
                # NameQualifier, if present is prefixed with a "/" to the value
                else
                 REXML::XPath.match(e,'a:NameID', { "a" => ASSERTION }).collect{|n|
                    (n.attributes['NameQualifier'] ? n.attributes['NameQualifier'] +"/" : '') + Utils.element_text(n)
                  }
                end
              }

              attributes.add(name, values.flatten)
            end
          end
          attributes
        end
      end

      # When this user session should expire at latest
      def session_expires_at
        @expires_at ||= begin
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
          parse_time(node, "SessionNotOnOrAfter")
        end
      end

      # Checks the status of the response for a "Success" code
      def success?
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
        end
      end

      # Conditions (if any) for the assertion to run
      def conditions
        @conditions ||= xpath_first_from_signed_assertion('/a:Conditions')
      end

      def not_before
        @not_before ||= parse_time(conditions, "NotBefore")
      end

      def not_on_or_after
        @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:Response/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= xpath_first_from_signed_assertion('/a:Issuer')
          Utils.element_text(node)
        end
      end

      # @return [Array] The Audience elements from the Contitions of the SAML Response.
      #
      def audiences
        @audiences ||= begin
          nodes = xpath_from_signed_assertion('/a:Conditions/a:AudienceRestriction/a:Audience')
          nodes.map { |node| Utils.element_text(node) }.reject(&:empty?)
        end
      end

      private

      def validation_error(message)
        raise ValidationError.new(message)
      end

      def validate(soft = true)
        validate_success_status       &&
        validate_num_assertion        &&
        validate_signed_elements      &&
        validate_structure(soft)      &&
        validate_response_state(soft) &&
        validate_conditions(soft)     &&
        validate_audience(soft)       &&
        document.validate_document(get_fingerprint, soft) &&
        success?
      end

      # Validates that the SAML Response only contains a single Assertion (encrypted or not).
      # @return [Boolean] True if the SAML Response contains one unique Assertion, otherwise False
      #
      def validate_num_assertion(soft = true)
        assertions = REXML::XPath.match(
          document,
          "//a:Assertion",
          { "a" => ASSERTION }
        )
        encrypted_assertions = REXML::XPath.match(
          document,
          "//a:EncryptedAssertion",
          { "a" => ASSERTION }
        )

        unless assertions.size != 0
          return soft ? false : validation_error("Encrypted assertion is not supported")
        end

        unless assertions.size + encrypted_assertions.size == 1
          return soft ? false : validation_error("SAML Response must contain 1 assertion")
        end

        true
      end

      # Validates the Signed elements
      # @return [Boolean] True if there is 1 or 2 Elements signed in the SAML Response
      #                        an are a Response or an Assertion Element, otherwise False if soft=True
      #
      def validate_signed_elements
        signature_nodes = REXML::XPath.match(
          document,
          "//ds:Signature",
          {"ds"=>DSIG}
        )
        signed_elements = []
        verified_seis = []
        verified_ids = []
        signature_nodes.each do |signature_node|
          signed_element = signature_node.parent.name
          if signed_element != 'Response' && signed_element != 'Assertion'
            return soft ? false : validation_error("Invalid Signature Element '#{signed_element}'. SAML Response rejected")
          end

          if signature_node.parent.attributes['ID'].nil?
            return soft ? false : validation_error("Signed Element must contain an ID. SAML Response rejected")
          end

          id = signature_node.parent.attributes.get_attribute("ID").value
          if verified_ids.include?(id)
            return soft ? false : validation_error("Duplicated ID. SAML Response rejected")
          end
          verified_ids.push(id)

          # Check that reference URI matches the parent ID and no duplicate References or IDs
          ref = REXML::XPath.first(signature_node, ".//ds:Reference", {"ds"=>DSIG})
          if ref
            uri = ref.attributes.get_attribute("URI")
            if uri && !uri.value.empty?
              sei = uri.value[1..-1]

              unless sei == id
                return soft ? false : validation_error("Found an invalid Signed Element. SAML Response rejected")
              end

              if verified_seis.include?(sei)
                return soft ? false : validation_error("Duplicated Reference URI. SAML Response rejected")
                return append_error("Duplicated Reference URI. SAML Response rejected")
              end

              verified_seis.push(sei)
            end
          end

          signed_elements << signed_element
        end

        unless signature_nodes.length < 3 && !signed_elements.empty?
          return soft ? false : validation_error("Found an unexpected number of Signature Element. SAML Response rejected")
        end

        true
      end

      # Validates the Status of the SAML Response
      # @return [Boolean] True if the SAML Response contains a Success code, otherwise False if soft == false
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_success_status
        return true if success?

        return false unless soft

        error_msg = 'The status code of the Response was not Success'
        status_error_msg = OneLogin::RubySaml::Utils.status_error_msg(error_msg, status_code, status_message)
        return validation_error(status_error_msg)
      end

      # Checks if the Status has the "Success" code
      # @return [Boolean] True if the StatusCode is Sucess
      #
      def success?
        status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
      end

      # @return [String] StatusCode value from a SAML Response.
      #
      def status_code
        @status_code ||= begin
          nodes = REXML::XPath.match(
            document,
            "/p:Response/p:Status/p:StatusCode",
            { "p" => PROTOCOL }
          )
          if nodes.size == 1
            node = nodes[0]
            code = node.attributes["Value"] if node && node.attributes

            unless code == "urn:oasis:names:tc:SAML:2.0:status:Success"
              nodes = REXML::XPath.match(
                document,
                "/p:Response/p:Status/p:StatusCode/p:StatusCode",
                { "p" => PROTOCOL }
              )
              statuses = nodes.collect do |inner_node|
                inner_node.attributes["Value"]
              end
              extra_code = statuses.join(" | ")
              if extra_code
                code = "#{code} | #{extra_code}"
              end
            end
            code
          end
        end
      end

      def validate_structure(soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml20protocol_schema.xsd'))
          @xml = Nokogiri::XML(self.document.to_s)
        end
        if soft
          @schema.validate(@xml).map{ return false }
        else
          @schema.validate(@xml).map{ |error| validation_error("#{error.message}\n\n#{@xml.to_s}") }
        end
      end

      def validate_response_state(soft = true)
        if response.empty?
          return soft ? false : validation_error("Blank response")
        end

        if settings.nil?
          return soft ? false : validation_error("No settings on response")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def xpath_first_from_signed_assertion(subelt=nil)
        node = REXML::XPath.first(
            document,
            "/p:Response/a:Assertion[@ID=$id]#{subelt}",
            { "p" => PROTOCOL, "a" => ASSERTION },
            { 'id' => document.signed_element_id }
        )
        node ||= REXML::XPath.first(
            document,
            "/p:Response[@ID=$id]/a:Assertion#{subelt}",
            { "p" => PROTOCOL, "a" => ASSERTION },
            { 'id' => document.signed_element_id }
        )
        node
      end

      # Extracts all the appearances that matchs the subelt (pattern)
      # Search on any Assertion that is signed, or has a Response parent signed
      # @param subelt [String] The XPath pattern
      # @return [Array of REXML::Element] Return all matches
      #
      def xpath_from_signed_assertion(subelt=nil)
        node = REXML::XPath.match(
            document,
            "/p:Response/a:Assertion[@ID=$id]#{subelt}",
            { "p" => PROTOCOL, "a" => ASSERTION },
            { 'id' => document.signed_element_id }
        )
        node.concat( REXML::XPath.match(
            document,
            "/p:Response[@ID=$id]/a:Assertion#{subelt}",
            { "p" => PROTOCOL, "a" => ASSERTION },
            { 'id' => document.signed_element_id }
        ))
      end

      def get_fingerprint
        if settings.idp_cert
          cert = OpenSSL::X509::Certificate.new(settings.idp_cert)
          Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
        else
          settings.idp_cert_fingerprint
        end
      end

      def validate_conditions(soft = true)
        return true if conditions.nil?
        return true if options[:skip_conditions]

        now = Time.now.utc

        if not_before && (now + (options[:allowed_clock_drift] || 0)) < not_before
          return soft ? false : validation_error("Current time is earlier than NotBefore condition")
        end

        if not_on_or_after && now >= not_on_or_after
          return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
        end

        true
      end

      def parse_time(node, attribute)
        if node && node.attributes[attribute]
          Time.parse(node.attributes[attribute])
        end
      end

      # Validates the Audience, (If the Audience match the Service Provider EntityID)
      # If fails, the error is added to the errors array
      # @return [Boolean] True if there is an Audience Element that match the Service Provider EntityID, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_audience(soft = true)
        return true if audiences.empty? || settings.sp_entity_id.nil? || settings.sp_entity_id.empty?

        unless audiences.include? settings.sp_entity_id
          s = audiences.count > 1 ? 's' : '';
          error_msg = "Invalid Audience#{s}. The audience#{s} #{audiences.join(',')}, did not match the expected audience #{settings.sp_entity_id}"
          return soft ? false : validation_error(error_msg)
        end

        true
      end
    end
  end
end

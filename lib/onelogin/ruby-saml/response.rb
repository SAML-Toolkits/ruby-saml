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
                  ["true", "1"].include?(e.attributes['xsi:nil']) ? nil : e.text.to_s
                # explicitly support saml2:NameID with saml2:NameQualifier if supplied in attributes
                # this is useful for allowing eduPersonTargetedId to be passed as an opaque identifier to use to
                # identify the subject in an SP rather than email or other less opaque attributes
                # NameQualifier, if present is prefixed with a "/" to the value
                else
                 REXML::XPath.match(e,'a:NameID', { "a" => ASSERTION }).collect{|n|
                    (n.attributes['NameQualifier'] ? n.attributes['NameQualifier'] +"/" : '') + n.text.to_s
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

      private

      def validation_error(message)
        raise ValidationError.new(message)
      end

      def validate(soft = true)
        validate_structure(soft)      &&
        validate_response_state(soft) &&
        validate_conditions(soft)     &&
        document.validate_document(get_fingerprint, soft) &&
        success?
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
    end
  end
end

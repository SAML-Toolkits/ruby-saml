require "xml_security"
require "onelogin/ruby-saml/attributes"

require "time"
require "nokogiri"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Authentication Response. SAML Response
    #
    class Response < SamlMessage
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      DSIG      = "http://www.w3.org/2000/09/xmldsig#"

      # TODO: Settings should probably be initialized too... WDYT?

      # OneLogin::RubySaml::Settings Toolkit settings
      attr_accessor :settings

      # Array with the causes [Array of strings]
      attr_accessor :errors

      attr_reader :options
      attr_reader :response
      attr_reader :document

      # Constructs the SAML Response. A Response Object that is an extension of the SamlMessage class.
      # @param response [String] A UUEncoded SAML response from the IdP.
      # @param options  [Hash]   Some options for the response validation process like skip the conditions validation
      #                          with the :skip_conditions, or allow a clock_drift when checking dates with :allowed_clock_drift
      #
      def initialize(response, options = {})
        @errors = []

        raise ArgumentError.new("Response cannot be nil") if response.nil?
        @options  = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response, @errors)
      end

      # Validates the SAML Response with the default values (soft = true)
      # @return [Boolean] TRUE if the SAML Response is valid
      #
      def is_valid?
        validate
      end

      # Hard aux function to validate the SAML Response (soft = false)
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
      # @param request_id [String|nil] request_id The ID of the AuthNRequest sent by this SP to the IdP (if was sent any)
      # @return [Boolean] TRUE if the SAML Response is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate!
        validate(false)
      end

      # @return [String] the NameID provided by the SAML response from the IdP.
      #
      def name_id
        @name_id ||= begin
          node = xpath_first_from_signed_assertion('/a:Subject/a:NameID')
          node.nil? ? nil : node.text
        end
      end

      # Gets the SessionIndex from the AuthnStatement.
      # Could be used to be stored in the local session in order
      # to be used in a future Logout Request that the SP could
      # send to the IdP, to set what specific session must be deleted
      # @return [String] SessionIndex Value
      #
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

          stmt_element = xpath_first_from_signed_assertion('/a:AttributeStatement')
          return attributes if stmt_element.nil?

          stmt_element.elements.each do |attr_element|
            name  = attr_element.attributes["Name"]
            values = attr_element.elements.collect{|e|
              # SAMLCore requires that nil AttributeValues MUST contain xsi:nil XML attribute set to "true" or "1"
              # otherwise the value is to be regarded as empty.
              ["true", "1"].include?(e.attributes['xsi:nil']) ? nil : e.text.to_s
            }

            attributes.add(name, values)
          end

          attributes
        end
      end

      # Gets the SessionNotOnOrAfter from the AuthnStatement.
      # Could be used to set the local session expiration (expire at latest)
      # @return [String] The SessionNotOnOrAfter value
      #
      def session_expires_at
        @expires_at ||= begin
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
          parse_time(node, "SessionNotOnOrAfter")
        end
      end

      # Checks if the Status has the "Success" code
      # @return [Boolean] True if the StatusCode is Sucess
      # 
      def success?
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
        end
      end

      # @return [String] the StatusMessage value from a SAML Response.
      #
      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusMessage", { "p" => PROTOCOL, "a" => ASSERTION })
          node.text if node
        end
      end

      # Gets the Condition Element of the SAML Response if exists.
      # (returns the first node that matches the supplied xpath)
      # @return [REXML::Element] Conditions Element if exists
      #
      def conditions
        @conditions ||= xpath_first_from_signed_assertion('/a:Conditions')
      end

      # Gets the NotBefore Condition Element value.
      # @return [Time] The NotBefore value in Time format
      #
      def not_before
        @not_before ||= parse_time(conditions, "NotBefore")
      end

      # Gets the NotOnOrAfter Condition Element value.
      # @return [Time] The NotOnOrAfter value in Time format
      #
      def not_on_or_after
        @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
      end

      # Gets the Issuer from the Response or the Assertion.
      # @return [String] The first Issuer found. First check Response, later the Assertion.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:Response/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= xpath_first_from_signed_assertion('/a:Issuer')
          node.nil? ? nil : node.text
        end
      end

      private

      # Validates the SAML Response (calls several validation methods)
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
      # @return [Boolean] True if the SAML Response is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(soft = true)
        valid_saml?(document, soft)      &&
        validate_response_state(soft) &&
        validate_conditions(soft)     &&
        validate_issuer(soft)         &&
        document.validate_document(get_fingerprint, soft, :fingerprint_alg => settings.idp_cert_fingerprint_algorithm) &&
        validate_success_status(soft)
      end

      # Validates the Status of the SAML Response
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
      # @return [Boolean] True if the SAML Response contains a Success code, otherwise False if soft == false
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_success_status(soft = true)
        if success?
          true
        else
          soft ? false : validation_error(status_message)
        end
      end

      # Validates the SAML Response against the specified schema.
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
      # @return [Boolean] True if the XML is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails 
      #
      def validate_structure(soft = true)
        xml = Nokogiri::XML(self.document.to_s)

        SamlMessage.schema.validate(xml).map do |error|
          if soft
            @errors << "Schema validation failed"
            break false
          else
            error_message = [error.message, xml.to_s].join("\n\n")

            @errors << error_message
            validation_error(error_message)
          end
        end
      end

      # Validates that the SAML Response provided in the initialization is not empty,
      # also check that the setting and the IdP cert were also provided
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
      # @return [Boolean] True if the required info is found, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
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

      # Extracts the first appearance that matchs the subelt (pattern)
      # Search on any Assertion that is signed, or has a Response parent signed
      # @param subelt [String] The XPath pattern
      # @return [REXML::Element | nil] If any matches, return the Element
      #
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

      # Calculates the fingerprint of the IdP x509 certificate.
      # @return [String] The fingerprint
      #
      def get_fingerprint
        if settings.idp_cert
          cert = OpenSSL::X509::Certificate.new(settings.idp_cert)
          fingerprint_alg = XMLSecurity::BaseDocument.new.algorithm(settings.idp_cert_fingerprint_algorithm).new
          fingerprint_alg.hexdigest(cert.to_der).upcase.scan(/../).join(":")
        else
          settings.idp_cert_fingerprint
        end
      end

      # Validates the Conditions. (If the response was initialized with the :skip_conditions option, this validation is skipped,
      # If the response was initialized with the :allowed_clock_drift option, the timing validations are relaxed by the allowed_clock_drift value)
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
      # @return [Boolean] True if satisfies the conditions, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_conditions(soft = true)
        return true if conditions.nil?
        return true if options[:skip_conditions]

        now = Time.now.utc

        if not_before && (now + (options[:allowed_clock_drift] || 0)) < not_before
          @errors << "Current time is earlier than NotBefore condition #{(now + (options[:allowed_clock_drift] || 0))} < #{not_before})"
          return soft ? false : validation_error("Current time is earlier than NotBefore condition")
        end

        if not_on_or_after && now >= not_on_or_after
          @errors << "Current time is on or after NotOnOrAfter condition (#{now} >= #{not_on_or_after})"
          return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
        end

        true
      end

      # Validates the Issuer (Of the SAML Response or of the SAML Assertion)
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
      # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_issuer(soft = true)
        return true if settings.idp_entity_id.nil?

        unless URI.parse(issuer) == URI.parse(settings.idp_entity_id)
          return soft ? false : validation_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
        end
        true
      end

      # Parse the attribute of a given node in Time format
      # @param node [REXML:Element] The node
      # @param attribute [String] The attribute name
      # @return [Time|nil] The parsed value
      #
      def parse_time(node, attribute)
        if node && node.attributes[attribute]
          Time.parse(node.attributes[attribute])
        end
      end
    end
  end
end

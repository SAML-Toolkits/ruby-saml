require "xml_security"
require "time"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML 2 Logout Response (SLO IdP initiated, Parser)
    #
    class Logoutresponse < SamlMessage

      # OneLogin::RubySaml::Settings Toolkit settings
      attr_accessor :settings

      # Array with the causes
      attr_accessor :errors

      attr_reader :options
      attr_reader :response
      attr_reader :document

      # Constructs the Logout Response. A Logout Response Object that is an extension of the SamlMessage class.
      # @param [String] A UUEncoded logout response from the IdP.
      # @param [OneLogin::RubySaml::Settings|nil] Toolkit settings
      #
      def initialize(response, settings = nil)
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        self.settings = settings

        @options = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response)
      end

      # An aux function to validate the Logout Response with the default values (soft = true)
      # @return [Boolean] TRUE if the Logout Response is valid
      #
      def is_valid?
        validate
      end

      # Another aux function to validate the Logout Response (soft = false)
      # @return [Boolean] TRUE if the SAML Response is valid
      #
      def validate!
        validate(false)
      end

      # After execute a validation process, if fails this method returns the causes
      # @return [Array] Empty Array if no errors, or an Array with the causes
      #
      def errors
        @errors
      end

      # Gets the InResponseTo attribute from the Logout Response.
      # @return [String|nil] The InResponseTo value if exists.
      #
      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      # Gets the Issuer from the Logout Response.
      # @return [String] Issuer
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      # Checks if the Status has the "Success" code
      # @return [Boolean] True if the StatusCode is Sucess
      # 
      def success?(soft = true)
        unless status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
          return soft ? false : validation_error("Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <#@status_code> ")
        end
        true
      end

      # Gets the StatusCode from a Logout Response.
      # @return [String] StatusCode Value
      #
      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      # Gets the StatusMessage from a SAML Response.
      # @return [String] StatusMessage Value
      #
      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusMessage", { "p" => PROTOCOL, "a" => ASSERTION })
          node.text if node
        end
      end

      # Validates the Logout Response (calls several validation methods)
      # If fails, the attribute errors will contains the reason for the invalidation.
      # @param [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @param [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
      # @return [Boolean|ValidationError] True if the Logout Response is valid, otherwise
      #                                   - False if soft=True
      #                                   - Raise a ValidationError if soft=False
      def validate(soft = true, request_id = nil)
        @errors = []
        valid_state?(soft) &&
        valid_in_response_to?(soft, request_id) &&
        valid_issuer?(soft) &&
        validate_structure(soft) &&
        validate_success_status(soft)
      end

      private

      # Validates that the Logout Response provided in the initialization is not empty, 
      # also check that the setting and the IdP cert were also provided 
      # If fails, the error is added to the errors array.
      # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean|ValidationError] True if the required info is found, otherwise
      #                                   - False if soft=True
      #                                   - Raise a ValidationError if soft=False 
      #
      def valid_state?(soft = true)
        if response.nil? or response.empty?
          error_msg = "Blank Logout Response"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        if settings.nil?
          error_msg = "No settings on Logout Response"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        if settings.issuer.nil?
          error_msg = "No issuer in settings"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          error_msg = "No fingerprint or certificate on settings"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        true
      end

      # Validates the Logout Response against the specified schema.
      # If fails, the error is added to the errors array
      # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean|ValidationError] True if the XML is valid, otherwise:
      #                                   - False if soft=True
      #                                   - Raise a ValidationError if soft=False 
      #
      def validate_structure(soft = true)
        xml = Nokogiri::XML(self.document.to_s)

        SamlMessage.schema.validate(xml).map do |error|
          if soft
            @errors << "Invalid Logout Response. Not match the saml-schema-protocol-2.0.xsd"
            break false
          else
            error_message = [error.message, xml.to_s].join("\n\n")

            @errors << error_message
            validation_error(error_message)
          end
        end
      end

      # Validates the Status of the Logout Response
      # If fails, the error is added to the errors array, including the StatusCode returned and the Status Message.
      # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)      
      # @return [Boolean|ValidationError] True if the Logout Response contains a Success code, otherwise: 
      #                                   - False if soft=True
      #                                   - Raise a ValidationError if soft=False 
      #
      def validate_success_status(soft = true)
        if success?
          true
        else
          error_msg = 'The status code of the Logout Response was not Success'
          unless status_code.nil?
            printable_code = status_code.split(':').pop
            error_msg +=  ', was ' + printable_code
          end

          unless status_message.nil?
            error_msg +=  ' -> ' + status_message
          end

          @errors << error_msg
          soft ? false : validation_error(error_msg)
        end
      end

      # Validates if the provided request_id match the inResponseTo value.
      # If fails, the error is added to the errors array
      # @param  [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
      # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean|ValidationError] True if there is no request_id or it match, otherwise:
      #                                   - False if soft=True
      #                                   - Raise a ValidationError if soft=False 
      #
      def valid_in_response_to?(soft = true, request_id = nil)
        return true if request_id.nil?

        unless request_id == in_response_to
          error_msg = "Logout Response does not match the request ID, expected: <#{request_id}>, but was: <#{in_response_to}>"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        true
      end

      # Validates the Issuer of the Logout Response
      # If fails, the error is added to the errors array
      # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean|ValidationError] True if the Issuer matchs the IdP entityId, otherwise:
      #                                   - False if soft=True
      #                                   - Raise a ValidationError if soft=False 
      #
      def valid_issuer?(soft = true)
        return true if self.settings.idp_entity_id.nil? or self.issuer.nil?

        unless URI.parse(self.issuer) == URI.parse(self.settings.idp_entity_id)
          error_msg = "Doesn't match the issuer, expected: <#{self.settings.idp_entity_id}>, but was: <#{issuer}>"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        true
      end

    end
  end
end

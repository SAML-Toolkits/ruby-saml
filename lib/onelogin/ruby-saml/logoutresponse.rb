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

      attr_reader :response
      attr_reader :options
      attr_reader :document

      # In order to validate that the response matches a given request, append
      # the option:
      #   :matches_request_id => REQUEST_ID
      #
      # It will validate that the logout response matches the ID of the request.
      # You can also do this yourself through the in_response_to accessor.
      #
      def initialize(response, settings = nil)
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        self.settings = settings

        @options = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response)
      end

      def validate!
        validate(false)
      end

      def validate(soft = true, request_id = nil)
        @errors = []
        valid_saml?(document, soft) && 
        valid_state?(soft) &&
        valid_in_response_to?(soft, request_id) &&
        valid_issuer?(soft) &&
        validate_success_status(soft)
      end

      # After execute a validation process, if fails this method returns the causes
      # @return [Array] Empty Array if no errors, or an Array with the causes
      #
      def errors
        @errors
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

      # Gets the StatusMessage from a SAML Response.
      # @return [String] StatusMessage Value
      #
      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusMessage", { "p" => PROTOCOL, "a" => ASSERTION })
          node.text if node
        end
      end

      def success?(soft = true)
        unless status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
          return soft ? false : validation_error("Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <#@status_code> ")
        end
        true
      end

      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= REXML::XPath.first(document, "/p:LogoutResponse/a:Assertion/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      private

      def valid_state?(soft = true)
        if response.empty?
          return soft ? false : validation_error("Blank response")
        end

        if settings.nil?
          return soft ? false : validation_error("No settings on response")
        end

        if settings.issuer.nil?
          return soft ? false : validation_error("No issuer in settings")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def valid_in_response_to?(soft = true, request_id = nil)
        return true if request_id.nil?

        unless request_id == in_response_to
          return soft ? false : validation_error("Logout Response does not match the request ID, expected: <#{request_id}>, but was: <#{in_response_to}>")
        end

        true
      end

      def valid_issuer?(soft = true)
        return true if self.settings.idp_entity_id.nil? or self.issuer.nil?

        unless URI.parse(self.issuer) == URI.parse(self.settings.idp_entity_id)
          return soft ? false : validation_error("Doesn't match the issuer, expected: <#{self.settings.issuer}>, but was: <#{issuer}>")
        end
        true
      end
    end
  end
end

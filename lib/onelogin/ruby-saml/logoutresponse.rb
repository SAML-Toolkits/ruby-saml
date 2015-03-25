require "xml_security"
require "onelogin/ruby-saml/saml_message"

require "time"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Logout Response (SLO IdP initiated, Parser)
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
      # @param response [String] A UUEncoded logout response from the IdP.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @raise [ArgumentError]
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
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @param request_id [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
      # @return [Boolean] TRUE if the SAML Response is valid
      #
      def validate!(soft=false, request_id = nil)
        validate(soft, request_id)
      end      

      # @return [String|nil] Gets the InResponseTo attribute from the Logout Response if exists.
      #
      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      # @return [String|nil] Gets the Destination attribute from the Logout Response if exists.
      #
      def destination
        @destination ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes['Destination']
        end
      end

      # @return [String] Gets the Issuer from the Logout Response.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      # Checks if the Status has the "Success" code
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean] True if the StatusCode is Sucess
      # @raise [ValidationError] if soft == false and validation fails
      # 
      def success?(soft = true)
        unless status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
          return soft ? false : validation_error("Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <#@status_code> ")
        end
        true
      end

      # @return [String] Gets the StatusCode from a Logout Response.
      #
      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      # @return [String] Gets the StatusMessage from a SAML Response.
      #
      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusMessage", { "p" => PROTOCOL, "a" => ASSERTION })
          node.text if node
        end
      end

      private

      # Gets the expected current_url
      # (Right now we read this url from the Sinle Logout Service of the Settings)
      # TODO: Calculate the real current_url and use it.
      # @return [String] The current url
      #
      def current_url
        @current_url ||= begin
          unless self.settings.nil? or self.settings.single_logout_service_url.nil?
            self.settings.single_logout_service_url
          end
        end
      end

      # Validates the Logout Response (calls several validation methods)
      # If fails, the attribute errors will contains the reason for the invalidation.
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @param request_id [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
      # @return [Boolean] True if the Logout Response is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(soft = true, request_id = nil)
        @errors = []
        valid_state?(soft) &&
        validate_success_status(soft) &&
        validate_structure(soft) &&
        valid_in_response_to?(soft, request_id) &&
        validate_destination(soft)   &&        
        valid_issuer?(soft)
      end

      private

      # Validates that the Logout Response provided in the initialization is not empty, 
      # also check that the setting and the IdP cert were also provided 
      # If fails, the error is added to the errors array.
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean] True if the required info is found, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
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
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean] True if the XML is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_structure(soft = true)
        valid = self.valid_saml?(self.document, soft)
        unless valid
          @errors << "Invalid Logout Response. Not match the saml-schema-protocol-2.0.xsd"
        end
        valid
      end

      # Validates the Status of the Logout Response
      # If fails, the error is added to the errors array, including the StatusCode returned and the Status Message.
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)      
      # @return [Boolean] True if the Logout Response contains a Success code, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
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
      # @param soft [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
      # @param request_id [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean] True if there is no request_id or it match, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
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

      # Validates the Destination, (if the Logout Response is received where expected)
      # If fails, the error is added to the errors array
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean] True if the destination is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_destination(soft = true)
        return true if destination.nil? or destination.empty? or settings.single_logout_service_url.nil? or settings.single_logout_service_url.empty?

        unless destination == current_url
          error_msg = "The Logout Response was received at #{self.destination} instead of #{current_url}"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        true
      end

      # Validates the Issuer of the Logout Response
      # If fails, the error is added to the errors array
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
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

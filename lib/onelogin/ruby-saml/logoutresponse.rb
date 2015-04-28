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
      attr_reader :get_params

      # Constructs the Logout Response. A Logout Response Object that is an extension of the SamlMessage class.
      # @param response   [String] A UUEncoded logout response from the IdP.
      # @param settings   [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @raise [ArgumentError]
      #
      def initialize(response, settings = nil)
        @errors = []
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        @settings = settings

        @options = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response)

      end

      # Append the cause to the errors array, and based on the value of soft, return false and raise
      # an exception
      def append_error(soft, error_msg)
        @errors << error_msg
        return soft ? false : validation_error(error_msg)
      end

      # Reset the errors array
      def reset_errors!
        @errors = []
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
      # @param get_params [Hash] In order to validate the In value we need to provide the GET parameters

      # @return [Boolean] TRUE if the SAML Response is valid
      #
      def validate!(soft=false, request_id = nil, get_params = nil)
        validate(soft, request_id, get_params)
      end      

      # @return [String|nil] Gets the InResponseTo attribute from the Logout Response if exists.
      #
      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(
            document,
            "/p:LogoutResponse",
            { "p" => PROTOCOL, "a" => ASSERTION }
          )
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      # @return [String|nil] Gets the Destination attribute from the Logout Response if exists.
      #
      def destination
        @destination ||= begin
          node = REXML::XPath.first(
            document,
            "/p:LogoutResponse",
            { "p" => PROTOCOL }
          )
          node.nil? ? nil : node.attributes['Destination']
        end
      end

      # @return [String] Gets the Issuer from the Logout Response.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document,
            "/p:LogoutResponse/a:Issuer",
            { "p" => PROTOCOL, "a" => ASSERTION }
          )
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
          return soft ? false : validation_error("Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <#{status_code}>")
        end
        true
      end

      # @return [String] Gets the StatusCode from a Logout Response.
      #
      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(
            document,
            "/p:LogoutResponse/p:Status/p:StatusCode",
            { "p" => PROTOCOL, "a" => ASSERTION }
          )
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      # @return [String] Gets the StatusMessage from a SAML Response.
      #
      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(
            document,
            "/p:LogoutResponse/p:Status/p:StatusMessage",
            { "p" => PROTOCOL, "a" => ASSERTION }
          )
          node.text if node
        end
      end

      # Gets the expected current_url
      # TODO: Calculate the real current_url and use it.
      #       (Right now we assume that the current url is the Sinle Logout Service URL)
      # @return [String] The current url
      #
      def current_url
        settings && settings.single_logout_service_url
      end

      # Validates the Logout Response (calls several validation methods)
      # If fails, the attribute errors will contains the reason for the invalidation.
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @param request_id [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
      # @param get_params [Hash] In order to validate the In value we need to provide the GET parameters
      # @return [Boolean] True if the Logout Response is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(soft = true, request_id = nil, get_params = nil)
        reset_errors!

        valid_state?(soft) &&
          validate_success_status(soft) &&
          validate_structure(soft) &&
          valid_in_response_to?(soft, request_id) &&
          validate_destination(soft) &&
          valid_issuer?(soft) &&
          validate_signature(soft, get_params)
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
        if response.nil? || response.empty?
          error_msg = "Blank Logout Response"
          return append_error(soft, error_msg)
        end

        if settings.nil?
          error_msg = "No settings on Logout Response"
          return append_error(soft, error_msg)
        end

        if settings.issuer.nil?
          error_msg = "No issuer in settings"
          return append_error(soft, error_msg)
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          error_msg = "No fingerprint or certificate on settings"
          return append_error(soft, error_msg)
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
        valid = valid_saml?(document, soft)
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
        return true if success?

        error_msg = 'The status code of the Logout Response was not Success'
        status_error_msg = OneLogin::RubySaml::Utils.status_error_msg(error_msg, status_code, status_message)
        append_error(soft, status_error_msg)
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
          return append_error(soft, error_msg)
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
        return true if destination.nil? || destination.empty? || settings.single_logout_service_url.nil? || settings.single_logout_service_url.empty?

        unless destination == current_url
          error_msg = "The Logout Response was received at #{destination} instead of #{current_url}"
          return append_error(soft, error_msg)
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
        return true if settings.idp_entity_id.nil? || issuer.nil?

        unless URI.parse(issuer) == URI.parse(settings.idp_entity_id)
          error_msg = "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>"
          return append_error(soft, error_msg)
        end

        true
      end

      # Validates the Signature if exists and GET parameters are provided
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @param get_params [Hash] In order to validate the In value we need to provide the GET parameters
      # @return [Boolean] True if not contains a Signature or if the Signature is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #      
      def validate_signature(soft = true, get_params = nil)
        return true if get_params.nil? || get_params['Signature'].nil? || settings.nil? || settings.get_idp_cert.nil?
        
        query_string = OneLogin::RubySaml::Utils.build_query(
          :type        => 'SAMLResponse',
          :data        => get_params['SAMLResponse'],
          :relay_state => get_params['RelayState'],
          :sig_alg     => get_params['SigAlg']
        )

        valid = OneLogin::RubySaml::Utils.verify_signature(
          :cert         => settings.get_idp_cert,
          :sig_alg      => get_params['SigAlg'],
          :signature    => get_params['Signature'],
          :query_string => query_string
        )

        unless valid
          error_msg = "Invalid Signature on Logout Response"
          return append_error(soft, error_msg)
        end
        true        
      end
    end
  end
end

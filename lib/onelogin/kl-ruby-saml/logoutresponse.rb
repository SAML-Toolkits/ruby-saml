require "kl_xml_security"
require "onelogin/kl-ruby-saml/saml_message"

require "time"

# Only supports SAML 2.0
module OneLogin
  module KlRubySaml

    # SAML2 Logout Response (SLO IdP initiated, Parser)
    #
    class Logoutresponse < SamlMessage

      # OneLogin::KlRubySaml::Settings Toolkit settings
      attr_accessor :settings

      # Array with the causes
      attr_accessor :errors

      attr_reader :document
      attr_reader :response
      attr_reader :options

      attr_accessor :soft

      # Constructs the Logout Response. A Logout Response Object that is an extension of the SamlMessage class.
      # @param response  [String] A UUEncoded logout response from the IdP.
      # @param settings  [OneLogin::KlRubySaml::Settings|nil] Toolkit settings
      # @param options   [Hash] Extra parameters. 
      #                    :matches_request_id It will validate that the logout response matches the ID of the request.
      #                    :get_params GET Parameters, including the SAMLResponse
      # @raise [ArgumentError] if response is nil
      #
      def initialize(response, settings = nil, options = {})
        @errors = []
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        @settings = settings

        if settings.nil? || settings.soft.nil?
          @soft = true
        else
          @soft = settings.soft
        end

        @options = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response)
      end

      # Append the cause to the errors array, and based on the value of soft, return false or raise
      # an exception
      def append_error(error_msg)
        @errors << error_msg
        return soft ? false : validation_error(error_msg)
      end

      # Reset the errors array
      def reset_errors!
        @errors = []
      end

      # Checks if the Status has the "Success" code
      # @return [Boolean] True if the StatusCode is Sucess
      # @raise [ValidationError] if soft == false and validation fails
      # 
      def success?
        unless status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
          return append_error("Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <#@status_code>")
        end
        true
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

      # @return [String] Gets the Issuer from the Logout Response.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(
            document,
            "/p:LogoutResponse/a:Issuer",
            { "p" => PROTOCOL, "a" => ASSERTION }
          )
          node.nil? ? nil : node.text
        end
      end

      # @return [String] Gets the StatusCode from a Logout Response.
      #
      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

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

      # Aux function to validate the Logout Response
      # @return [Boolean] TRUE if the SAML Response is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate
        reset_errors!

        valid_state? &&
        validate_success_status &&
        validate_structure &&
        valid_in_response_to? &&
        valid_issuer? &&
        validate_signature
      end

      private

      # Validates the Status of the Logout Response
      # If fails, the error is added to the errors array, including the StatusCode returned and the Status Message.
      # @return [Boolean] True if the Logout Response contains a Success code, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_success_status
        return true if success?

        error_msg = 'The status code of the Logout Response was not Success'
        status_error_msg = OneLogin::KlRubySaml::Utils.status_error_msg(error_msg, status_code, status_message)
        append_error(status_error_msg)
      end

      # Validates the Logout Response against the specified schema.
      # @return [Boolean] True if the XML is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails 
      #
      def validate_structure
        unless valid_saml?(document, soft)
          return append_error("Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd")
        end

        true
      end

       # Validates that the Logout Response provided in the initialization is not empty,
       # also check that the setting and the IdP cert were also provided
       # @return [Boolean] True if the required info is found, otherwise False if soft=True
       # @raise [ValidationError] if soft == false and validation fails
       #
      def valid_state?
        return append_error("Blank logout response") if response.empty?

        return append_error("No settings on logout response") if settings.nil?

        return append_error("No issuer in settings of the logout response") if settings.issuer.nil?

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return append_error("No fingerprint or certificate on settings of the logout response")
        end

        true
      end

      # Validates if a provided :matches_request_id matchs the inResponseTo value.
      # @param soft [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
      # @return [Boolean] True if there is no request_id or it match, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_in_response_to?
        return true unless options.has_key? :matches_request_id

        unless options[:matches_request_id] == in_response_to
          return append_error("Response does not match the request ID, expected: <#{options[:matches_request_id]}>, but was: <#{in_response_to}>")
        end

        true
      end

      # Validates the Issuer of the Logout Response
      # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_issuer?
        return true if settings.idp_entity_id.nil? || issuer.nil?

        unless URI.parse(issuer) == URI.parse(settings.idp_entity_id)
          return append_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
        end
        true
      end

      # Validates the Signature if it exists and the GET parameters are provided
      # @return [Boolean] True if not contains a Signature or if the Signature is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #      
      def validate_signature
        return true unless !options.nil?
        return true unless options.has_key? :get_params
        return true unless options[:get_params].has_key? 'Signature'
        return true if settings.nil? || settings.get_idp_cert.nil?
        
        query_string = OneLogin::KlRubySaml::Utils.build_query(
          :type        => 'SAMLResponse',
          :data        => options[:get_params]['SAMLResponse'],
          :relay_state => options[:get_params]['RelayState'],
          :sig_alg     => options[:get_params]['SigAlg']
        )

        valid = OneLogin::KlRubySaml::Utils.verify_signature(
          :cert         => settings.get_idp_cert,
          :sig_alg      => options[:get_params]['SigAlg'],
          :signature    => options[:get_params]['Signature'],
          :query_string => query_string
        )

        unless valid
          error_msg = "Invalid Signature on Logout Response"
          return append_error(error_msg)
        end
        true        
      end

    end
  end
end

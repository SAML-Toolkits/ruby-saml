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

      attr_reader :document
      attr_reader :response
      attr_reader :options

      # Constructs the Logout Response. A Logout Response Object that is an extension of the SamlMessage class.
      # @param response  [String] A UUEncoded logout response from the IdP.
      # @param settings  [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param options   [Hash] Extra parameters. 
      #                    :matches_request_id It will validate that the logout response matches the ID of the request.
      # @raise [ArgumentError] if response is nil
      #
      def initialize(response, settings = nil, options = {})
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        self.settings = settings

        @options = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response)
      end

      # Hard aux function to validate the Logout Response (soft = false)
      # @return [Boolean] TRUE if the SAML Response is valid
      # @raise [ValidationError] If validation fails
      #
      def validate!
        validate(false)
      end

      # Aux function to validate the Logout Response
      # @return [Boolean] TRUE if the SAML Response is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(soft = true)
        return false unless valid_saml?(document, soft) && valid_state?(soft)

        valid_in_response_to?(soft) && valid_issuer?(soft) && success?(soft)
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

      # @return [String|nil] Gets the InResponseTo attribute from the Logout Response if exists.
      #
      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      # @return [String] Gets the Issuer from the Logout Response.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= REXML::XPath.first(document, "/p:LogoutResponse/a:Assertion/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
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

      private

       # Validates that the Logout Response provided in the initialization is not empty,
       # also check that the setting and the IdP cert were also provided
       # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
       # @return [Boolean] True if the required info is found, otherwise False if soft=True
       # @raise [ValidationError] if soft == false and validation fails
       #
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

      # Validates if a provided :matches_request_id matchs the inResponseTo value.
      # @param soft [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
      # @return [Boolean] True if there is no request_id or it match, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_in_response_to?(soft = true)
        return true unless self.options.has_key? :matches_request_id

        unless self.options[:matches_request_id] == in_response_to
          return soft ? false : validation_error("Response does not match the request ID, expected: <#{self.options[:matches_request_id]}>, but was: <#{in_response_to}>")
        end

        true
      end

      # Validates the Issuer of the Logout Response
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
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

require 'zlib'
require 'time'
require 'nokogiri'

require "onelogin/ruby-saml/saml_message"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Logout Request (SLO IdP initiated, Parser)
    #
    class SloLogoutrequest < SamlMessage
      attr_reader :options
      attr_reader :request
      attr_reader :document

      # Constructs the Logout Request. A Logout Request Object that is an extension of the SamlMessage class.
      # @param request [String] A UUEncoded Logout Request from the IdP.
      # @param options [Hash]   Some options for the logout request validation process like allow a clock drift when checking dates with :allowed_clock_drift
      # @raise [ArgumentError] If Request is nil
      #
      def initialize(request, options = {})
        raise ArgumentError.new("Request cannot be nil") if request.nil?
        @options  = options
        @request = decode_raw_saml(request)
        @document = REXML::Document.new(@request)
      end

      # Validates the Logout Request with the default values (soft = true)
      # @return [Boolean] TRUE if the Logout Request is valid
      #
      def is_valid?
        validate
      end

      # Validates the Logout Request (soft = false)
      # @return [Boolean] TRUE if the Logout Request is valid
      # @raise [ValidationError] if validation fails
      #
      def validate!
        validate(false)
      end

      # @return [String] Gets the NameID of the Logout Request.
      #
      def name_id
        @name_id ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      # @return [String|nil] Gets the ID attribute from the Logout Request if exists.
      #
      def id
        return @id if @id
        element = REXML::XPath.first(document, "/p:LogoutRequest", {
            "p" => PROTOCOL} )
        return nil if element.nil?
        return element.attributes["ID"]
      end

      # @return [String] Gets the Issuer from the Logout Request.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      private

      # Hard aux function to validate the Logout Request
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
      # @return [Boolean] TRUE if the Logout Request is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(soft = true)
        valid_saml?(document, soft)  && validate_request_state(soft)
      end

      # Validates that the Logout Request provided in the initialization is not empty, 
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
      # @return [Boolean] True if the required info is found, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_request_state(soft = true)
        if request.empty?
          return soft ? false : validation_error("Blank request")
        end
        true
      end

    end
  end
end

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

      # Array with the causes [Array of strings]
      attr_accessor :errors

      attr_reader :options
      attr_reader :request
      attr_reader :document

      # Constructs the Logout Request. A Logout Request Object that is an extension of the SamlMessage class.
      # @param request [String] A UUEncoded Logout Request from the IdP.
      # @param options [Hash]   Some options for the logout request validation process like allow a clock drift when checking dates with :allowed_clock_drift
      # @raise [ArgumentError] If Request is nil
      #
      def initialize(request, options = {})
        @errors = []

        raise ArgumentError.new("Request cannot be nil") if request.nil?
        @options  = options
        @request = decode_raw_saml(request)
        @document = REXML::Document.new(@request)
      end

      # Append the cause to the errors array, and based on the value of soft, return false or raise
      # an exception
      def append_error(soft, error_msg)
        @errors << error_msg
        return soft ? false : validation_error(error_msg)
      end

      # Reset the errors array
      def reset_errors!
        @errors = []
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
        reset_errors!

        validate_request_state(soft) &&
        validate_structure(soft)
      end

      # Validates the Logout Request against the specified schema.
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the request is invalid or not)
      # @return [Boolean] True if the XML is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails 
      #
      def validate_structure(soft = true)
        unless valid_saml?(document, soft)
          return append_error(soft, "Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd")
        end

        true
      end

      # Validates that the Logout Request provided in the initialization is not empty, 
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
      # @return [Boolean] True if the required info is found, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_request_state(soft = true)
        return append_error(soft, "Blank logout request") if request.empty?

        true
      end

    end
  end
end

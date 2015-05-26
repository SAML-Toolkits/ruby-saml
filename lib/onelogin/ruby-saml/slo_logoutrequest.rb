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

      # OneLogin::RubySaml::Settings Toolkit settings
      attr_accessor :settings

      # Array with the causes [Array of strings]
      attr_accessor :errors

      attr_reader :document
      attr_reader :request
      attr_reader :options

      attr_accessor :soft

      # Constructs the Logout Request. A Logout Request Object that is an extension of the SamlMessage class.
      # @param request [String] A UUEncoded Logout Request from the IdP.
      # @param options [Hash]  :settings to provide the OneLogin::RubySaml::Settings object 
      #                        Or :allowed_clock_drift for the logout request validation process to allow a clock drift when checking dates with
      #
      # @raise [ArgumentError] If Request is nil
      #
      def initialize(request, options = {})
        @errors = []
        raise ArgumentError.new("Request cannot be nil") if request.nil?
        @options  = options

        @soft = true
        if !options.empty? && !options[:settings].nil?
          @settings = options[:settings]
          if !options[:settings].soft.nil? 
            @soft = options[:settings].soft
          end
        end

        @request = decode_raw_saml(request)
        @document = REXML::Document.new(@request)
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

      # Validates the Logout Request with the default values (soft = true)
      # @return [Boolean] TRUE if the Logout Request is valid
      #
      def is_valid?
        validate
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
      # @return [Boolean] TRUE if the Logout Request is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate
        reset_errors!

        validate_request_state &&
        validate_structure
      end

      # Validates the Logout Request against the specified schema.
      # @return [Boolean] True if the XML is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails 
      #
      def validate_structure
        unless valid_saml?(document, soft)
          return append_error("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd")
        end

        true
      end

      # Validates that the Logout Request provided in the initialization is not empty, 
      # @return [Boolean] True if the required info is found, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_request_state
        return append_error("Blank logout request") if request.empty?

        true
      end

    end
  end
end

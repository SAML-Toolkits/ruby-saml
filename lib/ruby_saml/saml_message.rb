# frozen_string_literal: true

require 'cgi'
require 'zlib'
require 'base64'
require 'nokogiri'
require 'ruby_saml/error_handling'
require 'ruby_saml/logging'

module RubySaml
  # SAML2 Message
  class SamlMessage

    # @return [Nokogiri::XML::Schema] The SAML 2.0 Protocol schema
    def self.schema
      @schema ||= File.open(File.expand_path('schemas/saml-schema-protocol-2.0.xsd', __dir__)) do |file|
        ::Nokogiri::XML::Schema(file)
      end
    end

    # @return [String|nil] Gets the Version attribute from the SAML Message if exists.
    def version(document)
      @version ||= root_attribute(document, 'Version')
    end

    # @return [String|nil] Gets the ID attribute from the SAML Message if exists.
    def id(document)
      @id ||= root_attribute(document, 'ID')
    end

    def root_attribute(document, attribute)
      return nil if document.nil?

      document.at_xpath(
        "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
        { "p" => RubySaml::XML::NS_PROTOCOL }
      )&.[](attribute)
    end

    # Validates the SAML Message against the specified schema.
    # @param document [Nokogiri::XML::Document] The message that will be validated
    # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the message is invalid or not)
    # @param check_malformed_doc [Boolean] check_malformed_doc Enable or Disable the check for malformed XML
    # @return [Boolean] True if the XML is valid, otherwise False, if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    def valid_saml?(document, soft = true, check_malformed_doc: true)
      begin
        xml = RubySaml::XML.safe_load_xml(document, check_malformed_doc: check_malformed_doc)
      rescue StandardError => error
        return false if soft
        raise ValidationError.new("XML load failed: #{error.message}") if error.message != "Empty document"
      end

      SamlMessage.schema.validate(xml).each do |schema_error|
        return false if soft
        raise ValidationError.new("#{schema_error.message}\n\n#{xml}")
      end

      true
    end

    private

    def check_malformed_doc?(settings)
      default_value = RubySaml::Settings::DEFAULTS[:check_malformed_doc]

      settings.nil? ? default_value : settings.check_malformed_doc
    end
  end
end

# frozen_string_literal: true

require 'cgi'
require 'zlib'
require 'base64'
require 'nokogiri'
require 'rexml/document'
require 'rexml/xpath'
require 'ruby_saml/error_handling'
require 'ruby_saml/logging'

# Only supports SAML 2.0
module RubySaml

  # SAML2 Message
  #
  class SamlMessage

    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

    BASE64_FORMAT = %r{\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z}
    @@mutex = Mutex.new

    # @return [Nokogiri::XML::Schema] Gets the schema object of the SAML 2.0 Protocol schema
    #
    def self.schema
      @@mutex.synchronize do
        Dir.chdir(File.expand_path('../../lib/ruby_saml/schemas', __dir__)) do
          ::Nokogiri::XML::Schema(File.read("saml-schema-protocol-2.0.xsd"))
        end
      end
    end

    # @return [String|nil] Gets the Version attribute from the SAML Message if exists.
    #
    def version(document)
      @version ||= begin
        node = REXML::XPath.first(
          document,
          "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
          { "p" => PROTOCOL }
        )
        node.nil? ? nil : node.attributes['Version']
      end
    end

    # @return [String|nil] Gets the ID attribute from the SAML Message if exists.
    #
    def id(document)
      @id ||= begin
        node = REXML::XPath.first(
          document,
          "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
          { "p" => PROTOCOL }
        )
        node.nil? ? nil : node.attributes['ID']
      end
    end

    # Validates the SAML Message against the specified schema.
    # @param document [REXML::Document] The message that will be validated
    # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the message is invalid or not)
    # @param check_malformed_doc [Boolean] check_malformed_doc Enable or Disable the check for malformed XML
    # @return [Boolean] True if the XML is valid, otherwise False, if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    def valid_saml?(document, soft = true, check_malformed_doc: true)
      begin
        xml = RubySaml::XML.safe_load_nokogiri(document, check_malformed_doc: check_malformed_doc)
      rescue StandardError => error
        return false if soft
        raise ValidationError.new("XML load failed: #{error.message}")
      end

      SamlMessage.schema.validate(xml).each do |schema_error|
        return false if soft
        raise ValidationError.new("#{schema_error.message}\n\n#{xml}")
      end

      true
    end

    private

    # Base64 decode and try also to inflate a SAML Message
    # @param saml [String] The deflated and encoded SAML Message
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @return [String] The plain SAML Message
    #
    def decode_raw_saml(saml, settings = nil)
      return saml unless base64_encoded?(saml)

      settings ||= RubySaml::Settings.new
      if saml.bytesize > settings.message_max_bytesize
        raise ValidationError.new("Encoded SAML Message exceeds #{settings.message_max_bytesize} bytes, so was rejected")
      end

      decoded = decode(saml)
      message = begin
        inflate(decoded)
      rescue StandardError
        decoded
      end

      if message.bytesize > settings.message_max_bytesize
        raise ValidationError.new("SAML Message exceeds #{settings.message_max_bytesize} bytes, so was rejected")
      end

      message
    end

    # Deflate, base64 encode and url-encode a SAML Message (To be used in the HTTP-redirect binding)
    # @param saml [String] The plain SAML Message
    # @param settings_or_compress [true|false|RubySaml::Settings|nil] Whether or not the SAML should be deflated.
    #   The usage of RubySaml::Settings here is deprecated.
    # @return [String] The deflated and encoded SAML Message (encoded if the compression is requested)
    def encode_raw_saml(saml, settings_or_compress = false)
      if settings_or_compress.is_a?(TrueClass)
        saml = deflate(saml)
      elsif settings_or_compress.respond_to?(:compress_request)
        Logging.deprecate('Please change the second argument of `encode_raw_saml_message` to a boolean ' \
                          'indicating whether or not to use compression. Using a boolean will be required ' \
                          'in RubySaml 2.1.0.')
        saml = deflate(saml) if settings_or_compress.compress_request
      end

      CGI.escape(encode(saml))
    end

    # Base 64 decode method
    # @param string [String] The string message
    # @return [String] The decoded string
    #
    def decode(string)
      Base64.decode64(string)
    end

    # Base 64 encode method
    # @param string [String] The string
    # @return [String] The encoded string
    #
    def encode(string)
      Base64.strict_encode64(string)
    end

    # Check if a string is base64 encoded
    # @param string [String] string to check the encoding of
    # @return [true, false] whether or not the string is base64 encoded
    #
    def base64_encoded?(string)
      !!string.gsub(/[\r\n]|\\r|\\n|\s/, "").match(BASE64_FORMAT)
    end

    # Inflate method
    # @param deflated [String] The string
    # @return [String] The inflated string
    #
    def inflate(deflated)
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(deflated)
    end

    # Deflate method
    # @param inflated [String] The string
    # @return [String] The deflated string
    #
    def deflate(inflated)
      Zlib::Deflate.deflate(inflated, Zlib::BEST_COMPRESSION)[2..-5]
    end

    def check_malformed_doc?(settings)
      default_value = RubySaml::Settings::DEFAULTS[:check_malformed_doc]

      settings.nil? ? default_value : settings.check_malformed_doc
    end
  end
end

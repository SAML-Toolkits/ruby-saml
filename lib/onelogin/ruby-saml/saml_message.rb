require 'cgi'
require 'zlib'
require 'base64'
require 'nokogiri'
require 'rexml/document'
require 'rexml/xpath'
require "onelogin/ruby-saml/error_handling"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Message
    #
    class SamlMessage
      include REXML

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol".freeze

      BASE64_FORMAT = %r{\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z}

      # @return [Nokogiri::XML::Schema] Gets the schema object of the SAML 2.0 Protocol schema
      #
      def self.schema
        path = File.expand_path("../../../schemas/saml-schema-protocol-2.0.xsd", __FILE__)
        File.open(path) do |file|
          ::Nokogiri::XML::Schema(file)
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
      def valid_saml?(document, soft = true, check_malformed_doc = true)
        begin
          xml = XMLSecurity::BaseDocument.safe_load_xml(document, check_malformed_doc)
        rescue StandardError => error
          return false if soft
          raise ValidationError.new("XML load failed: #{error.message}")
        end

        SamlMessage.schema.validate(xml).map do |schema_error|
          return false if soft
          raise ValidationError.new("#{schema_error.message}\n\n#{xml}")
        end
      end

      private

      # Base64 decode and try also to inflate a SAML Message
      # @param saml [String] The deflated and encoded SAML Message
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @return [String] The plain SAML Message
      #
      def decode_raw_saml(saml, settings = nil)
        settings = OneLogin::RubySaml::Settings.new if settings.nil?
        if saml.bytesize > settings.message_max_bytesize
          raise ValidationError.new("Encoded SAML Message exceeds " + settings.message_max_bytesize.to_s + " bytes, so was rejected")
        end

        return saml unless base64_encoded?(saml)

        saml = try_inflate(decode(saml), settings.message_max_bytesize)

        if saml.bytesize > settings.message_max_bytesize
            raise ValidationError.new("SAML Message exceeds " + settings.message_max_bytesize.to_s + " bytes, so was rejected")
        end

        saml
      end

      # Deflate, base64 encode and url-encode a SAML Message (To be used in the HTTP-redirect binding)
      # @param saml [String] The plain SAML Message
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @return [String] The deflated and encoded SAML Message (encoded if the compression is requested)
      #
      def encode_raw_saml(saml, settings)
        saml = deflate(saml) if settings.compress_request

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
        if Base64.respond_to?('strict_encode64')
          Base64.strict_encode64(string)
        else
          Base64.encode64(string).gsub(/\n/, "")
        end
      end

      # Check if a string is base64 encoded
      # @param string [String] string to check the encoding of
      # @return [true, false] whether or not the string is base64 encoded
      #
      def base64_encoded?(string)
        string.gsub(/\s|\\r|\\n/, '').match?(BASE64_FORMAT)
      end

      # Attempt inflating a string, if it fails, return the original string.
      # @param data [String] The string
      # @param max_bytesize [Integer] The maximum allowed size of the SAML Message,
      #   to prevent a possible DoS attack.
      # @return [String] The inflated or original string
      def try_inflate(data, max_bytesize = nil)
        inflate(data, max_bytesize)
      rescue Zlib::Error
        data
      end

      # Inflate method.
      # @param deflated [String] The string
      # @param max_bytesize [Integer] The maximum allowed size of the SAML Message,
      #   to prevent a possible DoS attack.
      # @return [String] The inflated string
      def inflate(deflated, max_bytesize = nil)
        unless max_bytesize.nil?
          inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)

          # Use a StringIO buffer to build the inflated message incrementally.
          buffer = StringIO.new

          inflater.inflate(deflated) do |chunk|
            if buffer.length + chunk.bytesize > max_bytesize
              inflater.close
              raise ValidationError, "SAML Message exceeds #{max_bytesize} bytes during decompression, so was rejected"
            end
            buffer << chunk
          end

          final_chunk = inflater.finish
          unless final_chunk.empty?
            if buffer.length + final_chunk.bytesize > max_bytesize
              raise ValidationError, "SAML Message exceeds #{max_bytesize} bytes during decompression, so was rejected"
            end
            buffer << final_chunk
          end

          inflater.close
          buffer.string
        else
          Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(deflated)
        end
      end

      # Deflate method
      # @param inflated [String] The string
      # @return [String] The deflated string
      #
      def deflate(inflated)
        Zlib::Deflate.deflate(inflated, 9)[2..-5]
      end

      def check_malformed_doc?(settings)
        default_value = OneLogin::RubySaml::Settings::DEFAULTS[:check_malformed_doc]

        settings.nil? ? default_value : settings.check_malformed_doc
      end
    end
  end
end

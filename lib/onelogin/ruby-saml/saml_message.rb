require 'cgi'
require 'zlib'
require 'base64'
require "nokogiri"
require "rexml/document"
require "rexml/xpath"
require "thread"

module OneLogin
  module RubySaml

    # SAML2 Message
    #
    class SamlMessage
      include REXML

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

      # @return [String|nil] Gets the Version attribute from the SAML Message if exists.
      #
      def version(document)
        @recipient ||= begin
          node = REXML::XPath.first(document, "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes['Version']
        end
      end

      # @return [String|nil] Gets the ID attribute from the SAML Message if exists.
      #
      def id(document)
        @id ||= begin
          node = REXML::XPath.first(document, "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes['ID']
        end
      end

      # @return [Nokogiri::XML::Schema] Gets the schema object of the SAML 2.0 Protocol schema
      #
      def self.schema
        @schema ||= Mutex.new.synchronize do
          Dir.chdir(File.expand_path("../../../schemas", __FILE__)) do
            ::Nokogiri::XML::Schema(File.read("saml-schema-protocol-2.0.xsd"))
          end
        end
      end

      # Validates the SAML Response against the specified schema.
      # @param document [REXML::Document] The message that will be validated
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the message is invalid or not)
      # @return [Boolean] True if the XML is valid, otherwise:
      #                                   - False if soft=True
      # @raise [ValidationError] if soft == false and validation fails 
      #
      def valid_saml?(document, soft = true)
        xml = Nokogiri::XML(document.to_s)

        SamlMessage.schema.validate(xml).map do |error|
          break false if soft
          error_message = [error.message, xml.to_s].join("\n\n")
          validation_error(error_message)
        end
      end

      # Raise a ValidationError with the provided message
      # @return message [String] Message of the exception
      # @raise [ValidationError]
      #
      def validation_error(message)
        raise ValidationError.new(message)
      end

      private

      # Base64 decode and inflate a SAML Message
      # @param saml [String] The deflated and encoded SAML Message
      # @return [String] The plain SAML Message

      def decode_raw_saml(saml)
        if saml =~ /^</
          return saml
        elsif (decoded  = decode(saml)) =~ /^</
          return decoded
        elsif (inflated = inflate(decoded)) =~ /^</
          return inflated
        end

        return nil
      end

      # Deflate, base64 encode and url-encode a SAML Message (To be used in the HTTP-redirect binding)
      # @param saml [String] The plain SAML Message
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @return [String] The deflated and encoded SAML Message (encoded if the compression is requested)
      def encode_raw_saml(saml, settings)
        saml           = Zlib::Deflate.deflate(saml, 9)[2..-5] if settings.compress_request
        base64_saml    = Base64.encode64(saml)
        return CGI.escape(base64_saml)
      end

      # Base 64 decode method
      # @param saml [String] The string message
      # @return [String] The decoded string
      def decode(encoded)
        Base64.decode64(encoded)
      end

      # Base 64 encode method
      # @param saml [String] The string
      # @return [String] The encoded string
      def encode(encoded)
        Base64.encode64(encoded).gsub(/\n/, "")
      end

      # URL-decode method
      # @param saml [String] The string
      # @return [String] The url-encoded string
      def escape(unescaped)
        CGI.escape(unescaped)
      end

      # URL-encode method
      # @param saml [String] The url-encoded string
      # @return [String] The url-decoded string
      def unescape(escaped)
        CGI.unescape(escaped)
      end

      # Inflate method
      # @param saml [String] The string
      # @return [String] The inflated string
      def inflate(deflated)
        zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        zlib.inflate(deflated)
      end

      # Deflate method
      # @param saml [String] The string
      # @return [String] The deflated string
      def deflate(inflated)
        Zlib::Deflate.deflate(inflated, 9)[2..-5]
      end

    end
  end
end

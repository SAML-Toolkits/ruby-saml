require 'cgi'
require 'zlib'
require 'base64'
require "nokogiri"
require "rexml/document"
require "rexml/xpath"
require "thread"

module OneLogin
  module RubySaml
    class SamlMessage
      include REXML

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

      def self.schema
        @schema ||= Mutex.new.synchronize do
          Dir.chdir(File.expand_path("../../../schemas", __FILE__)) do
            ::Nokogiri::XML::Schema(File.read("saml-schema-protocol-2.0.xsd"))
          end
        end
      end

      def valid_saml?(document, soft = true)
        xml = Nokogiri::XML(document.to_s)

        SamlMessage.schema.validate(xml).map do |error|
          break false if soft
          validation_error("#{error.message}\n\n#{xml.to_s}")
        end
      end

      def validation_error(message)
        raise ValidationError.new(message)
      end

      private

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

      def encode_raw_saml(saml, settings)
        saml           = Zlib::Deflate.deflate(saml, 9)[2..-5] if settings.compress_request
        base64_saml    = Base64.encode64(saml)
        return CGI.escape(base64_saml)
      end

      def decode(encoded)
        Base64.decode64(encoded)
      end

      def encode(encoded)
        Base64.encode64(encoded).gsub(/\n/, "")
      end

      def escape(unescaped)
        CGI.escape(unescaped)
      end

      def unescape(escaped)
        CGI.unescape(escaped)
      end

      def inflate(deflated)
        zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        zlib.inflate(deflated)
      end

      def deflate(inflated)
        Zlib::Deflate.deflate(inflated, 9)[2..-5]
      end

    end
  end
end

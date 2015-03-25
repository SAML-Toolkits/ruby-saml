require 'cgi'
require 'zlib'
require 'base64'
require 'nokogiri'
require 'rexml/document'
require 'rexml/xpath'
require 'thread'

module OneLogin
  module RubySaml
    class SamlMessage
      include REXML

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

      BASE64_FORMAT = %r(\A[A-Za-z0-9+/]{4}*[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=?\Z)

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

      ##
      # Take a SAML object provided by +saml+, determine its status and return
      # a decoded XML as a String.
      #
      # Since SAML decided to use the RFC1951 and therefor has no zlib markers,
      # the only reliable method of deciding whether we have a zlib stream or not
      # is to try and inflate it and fall back to the base64 decoded string if
      # the stream contains errors.
      def decode_raw_saml(saml)
        return saml unless base64_encoded?(saml)

        decoded = decode(saml)
        begin
          inflate(decoded)
        rescue
          decoded
        end
      end

      def encode_raw_saml(saml, settings)
        saml = deflate(saml) if settings.compress_request

        CGI.escape(Base64.encode64(saml))
      end

      def decode(encoded)
        Base64.decode64(encoded)
      end

      def encode(encoded)
        Base64.encode64(encoded).gsub(/\n/, "")
      end

      # Check if a string is base64 encoded
      #
      # @param string [String] string to check the encoding of
      # @return [true, false] whether or not the string is base64 encoded
      def base64_encoded?(string)
        !!string.gsub(/[\r\n]|\\r|\\n/, "").match(BASE64_FORMAT)
      end

      def inflate(deflated)
        Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(deflated)
      end

      def deflate(inflated)
        Zlib::Deflate.deflate(inflated, 9)[2..-5]
      end
    end
  end
end

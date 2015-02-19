require 'cgi'
require 'zlib'
require 'base64'
require "nokogiri"
require "rexml/document"
require "rexml/xpath"
require "thread"
require "xmlenc"

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

      def decrypt_saml(decoded_saml, private_key_file_path=nil)
        noko_xml = Nokogiri::XML(decoded_saml)
        if ((noko_xml.xpath('//saml:EncryptedAssertion', {:saml => "urn:oasis:names:tc:SAML:2.0:assertion"}).count > 0) && !private_key_file_path.nil?)
          key_pem = File.read(private_key_file_path)
          encrypted_response = Xmlenc::EncryptedDocument.new(decoded_saml)
          private_key = OpenSSL::PKey::RSA.new(key_pem)
          decrypted_string = encrypted_response.decrypt(private_key)
          decrypted_doc = Nokogiri::XML(decrypted_string) do |config|
            # config.strict.nonet # for an ideal world
          end
          saml_namespace = {:saml => "urn:oasis:names:tc:SAML:2.0:assertion"}
          assertion = decrypted_doc.xpath("//saml:EncryptedAssertion/saml:Assertion", saml_namespace)
          assertion = decrypted_doc.xpath("//saml:assertion", saml_namespace) if assertion.empty?
          assertion = decrypted_doc.xpath("//saml:Assertion", saml_namespace) if assertion.empty?
          assertion = decrypted_doc.xpath("//saml:ASSERTION", saml_namespace) if assertion.empty?
          if assertion.empty?
            validation_error("XML document seems to be malformed and does not have correct Nodes")
          else
            return assertion.first.to_s.gsub(" ", '').gsub("\n", '')
          end
        end
        return decoded_saml
      end
      
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

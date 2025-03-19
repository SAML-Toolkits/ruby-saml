# frozen_string_literal: true

require_relative '../test_helper'

class XmlDecoderTest < Minitest::Test
  describe 'RubySaml::XML::Decoder' do
    let(:response_document_xml) { read_response("adfs_response_xmlns.xml") }
    let(:response_document) { read_response("response_unsigned_xml_base64") }

    describe '#decode_message' do
      it "decodes raw base64-encoded SAML" do
        decoded = RubySaml::XML::Decoder.decode_message(logout_request_base64)
        assert_equal logout_request_original, decoded
      end

      it "decodes and inflates deflated base64-encoded SAML" do
        decoded = RubySaml::XML::Decoder.decode_message(logout_request_deflated_base64)
        assert_equal logout_request_original, decoded
      end

      it "handles non-base64 input by returning it unchanged" do
        plain_text = "This is not base64 encoded"
        result = RubySaml::XML::Decoder.decode_message(plain_text)
        assert_equal plain_text, result
      end

      it "uses default max_bytesize when not provided" do
        # Create a message just over the default size limit
        large_text = "A" * (RubySaml::XML::Decoder::DEFAULT_MAX_BYTESIZE + 100)
        encoded = Base64.strict_encode64(large_text)

        assert_raises(RubySaml::ValidationError, "Encoded SAML Message exceeds #{RubySaml::XML::Decoder::DEFAULT_MAX_BYTESIZE} bytes, so was rejected") do
          RubySaml::XML::Decoder.decode_message(encoded)
        end
      end

      it "uses custom max_bytesize when provided" do
        custom_max = 1000
        large_text = 'A' * (custom_max + 100)
        encoded = Base64.strict_encode64(large_text)

        assert_raises(RubySaml::ValidationError, "Encoded SAML Message exceeds #{custom_max} bytes, so was rejected") do
          RubySaml::XML::Decoder.decode_message(encoded, custom_max)
        end
      end

      it "checks size after inflation" do
        large_text = 'A' * (RubySaml::XML::Decoder::DEFAULT_MAX_BYTESIZE + 100)
        deflated = Zlib::Deflate.deflate(large_text, Zlib::BEST_COMPRESSION)[2..-5]
        encoded = Base64.strict_encode64(deflated)

        assert encoded.bytesize < RubySaml::XML::Decoder::DEFAULT_MAX_BYTESIZE
        assert_raises(RubySaml::ValidationError, "SAML Message exceeds #{RubySaml::XML::Decoder::DEFAULT_MAX_BYTESIZE} bytes, so was rejected") do
          RubySaml::XML::Decoder.decode_message(encoded, RubySaml::XML::Decoder::DEFAULT_MAX_BYTESIZE)
        end
      end

      it "checks size after inflation with custom max" do
        custom_max = 1000
        large_text = 'A' * (custom_max + 100)
        deflated = Zlib::Deflate.deflate(large_text, Zlib::BEST_COMPRESSION)[2..-5]
        encoded = Base64.strict_encode64(deflated)

        assert encoded.bytesize < custom_max
        assert_raises(RubySaml::ValidationError, "SAML Message exceeds #{custom_max} bytes, so was rejected") do
          RubySaml::XML::Decoder.decode_message(encoded, custom_max)
        end
      end

      it "rejects Zlib bomb attacks" do
        # Create a message that when inflated would be extremely large
        bomb_prefix = <<~XML
          <?xml version='1.0' encoding='UTF-8'?>
          <samlp:LogoutRequest xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d' Version='2.0' IssueInstant='2014-07-18T01:13:06Z' Destination='http://idp.example.com/SingleLogoutService.php'>
          <saml:Issuer>
        XML

        bomb_suffix = <<~XML
          </saml:Issuer>
          <saml:NameID SPNameQualifier='http://sp.example.com/demo1/metadata.php' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</saml:NameID>
          </samlp:LogoutRequest>
        XML

        bomb_data = bomb_prefix + 'A' * (200_000 * 1024) + bomb_suffix
        bomb = Base64.strict_encode64(Zlib::Deflate.deflate(bomb_data, 9)[2..-5])

        assert_raises(RubySaml::ValidationError) do
          RubySaml::XML::Decoder.decode_message(bomb)
        end
      end
    end

    describe '#encode_message' do
      it "base64 encodes SAML without compression by default" do
        encoded = RubySaml::XML::Decoder.encode_message(logout_request_document)
        decoded = Base64.decode64(encoded)
        assert_equal logout_request_document, decoded
      end

      it "base64 encodes and deflates SAML when compression is requested" do
        encoded = RubySaml::XML::Decoder.encode_message(logout_request_document, compress: true)
        # We need to decode and inflate to verify
        decoded = Base64.decode64(encoded)
        inflated = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(decoded)
        assert_equal logout_request_document, inflated
      end

      it "produces output that can be decoded by decode_message (round trip)" do
        # Without compression
        encoded = RubySaml::XML::Decoder.encode_message(logout_request_document)
        decoded = RubySaml::XML::Decoder.decode_message(encoded)
        assert_equal logout_request_document, decoded

        # With compression
        encoded_compressed = RubySaml::XML::Decoder.encode_message(logout_request_document, compress: true)
        decoded_compressed = RubySaml::XML::Decoder.decode_message(encoded_compressed)
        assert_equal logout_request_document, decoded_compressed
      end
    end
  end
end

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RubySamlTest < Minitest::Test

  describe "SamlMessage" do

    let(:settings) { OneLogin::RubySaml::Settings.new }
    let(:saml_message) { OneLogin::RubySaml::SamlMessage.new }
    let(:response_document) { read_response("response_unsigned_xml_base64") }
    let(:response_document_xml) { read_response("adfs_response_xmlns.xml") }

    it "return decoded raw saml" do
      decoded_raw = saml_message.send(:decode_raw_saml, logout_request_deflated_base64)
      assert logout_request_document, decoded_raw
    end

    it "return encoded raw saml" do
      settings.compress_request = true
      encoded_raw = saml_message.send(:encode_raw_saml, logout_request_document, settings)
      assert logout_request_deflated_base64, encoded_raw

      settings.compress_request = false
      deflated = saml_message.send(:deflate, logout_request_deflated_base64)
      encoded_raw = saml_message.send(:encode_raw_saml, deflated, settings)
      assert logout_request_deflated_base64, encoded_raw
    end

    it "return decoded string" do
      decoded = saml_message.send(:decode, response_document)
      assert response_document_xml, decoded

      decoded = saml_message.send(:decode, logout_request_base64)
      assert logout_request_document, decoded
    end

    it "return encoded string" do
      encoded = saml_message.send(:encode, response_document_xml)
      assert response_document, encoded

      encoded = saml_message.send(:encode, logout_request_document)
      assert logout_request_base64, encoded
    end

    it "return deflated string" do
      deflated = saml_message.send(:deflate, logout_request_document)
      encoded_deflated = saml_message.send(:encode, deflated)
      assert logout_request_deflated_base64, encoded_deflated
    end

    it "return inflated string" do
      decoded = saml_message.send(:decode, logout_request_deflated_base64)
      decoded_inflated = saml_message.send(:inflate, decoded)
      assert response_document_xml, decoded_inflated
    end

    describe "Prevent Zlib bomb attack" do
      let(:bomb) { Base64.encode64(Zlib::Deflate.deflate(bomb_data, 9)[2..-5]) }
      let(:bomb_data) { bomb_prefix + "A" * (200000 * 1024) + bomb_suffix }
      let(:bomb_prefix) { """<?xml version='1.0' encoding='UTF-8'?>
        <samlp:LogoutRequest xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d' Version='2.0' IssueInstant='2014-07-18T01:13:06Z' Destination='http://idp.example.com/SingleLogoutService.php'>
        <saml:Issuer>""" }
      let(:bomb_suffix) { """</saml:Issuer>
        <saml:NameID SPNameQualifier='http://sp.example.com/demo1/metadata.php' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</saml:NameID>
     </samlp:LogoutRequest>""" }

      it "raises error when SAML Message exceed the allowed bytes" do
        assert_raises(OneLogin::RubySaml::ValidationError, "Encoded SAML Message exceeds #{OneLogin::RubySaml::Settings::DEFAULTS[:message_max_bytesize]} bytes, so was rejected") do
            saml_message = OneLogin::RubySaml::SamlMessage.new
            saml_message.send(:decode_raw_saml, bomb)
        end
      end

      describe 'with a custom setting for message_max_bytesize' do
        let(:message_max_bytesize) { 100_00 }
        let(:settings) { OneLogin::RubySaml::Settings.new({:message_max_bytesize => message_max_bytesize}) }

        it 'uses the custom setting' do
          assert_raises(OneLogin::RubySaml::ValidationError, "Encoded SAML Message exceeds #{message_max_bytesize} bytes, so was rejected") do
            saml_message = OneLogin::RubySaml::SamlMessage.new
            saml_message.send(:decode_raw_saml, bomb, settings)
          end
        end
      end
    end
  end
end

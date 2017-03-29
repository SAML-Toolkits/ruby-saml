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

    describe 'Prevent DOS attack with a 1000:1 compressed saml document setting inflate option to false' do
      let(:disabled_inflate_settings){OneLogin::RubySaml::Settings.new(inflate: false)}
      let(:deflated_saml){logout_request_deflated_base64}
      let(:non_deflated_saml){logout_request_base64}
      it "return decoded raw saml" do
        decoded_raw = saml_message.send(:decode_raw_saml, non_deflated_saml, disabled_inflate_settings).gsub(/\r|\n/, '').encode('utf-8')
        actual_message = read_logout_request("slo_request.xml").gsub(/\r|\n/, '').encode('utf-8')
        assert_equal decoded_raw, actual_message
      end
      it "does not return inflated raw saml" do
        decoded_raw = saml_message.send(:decode_raw_saml, deflated_saml, disabled_inflate_settings)
        assert_equal Base64.decode64(deflated_saml), decoded_raw
      end
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
  end
end

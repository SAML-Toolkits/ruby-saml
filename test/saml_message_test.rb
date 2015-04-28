require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RubySamlTest < Minitest::Test

  describe "SamlMessage" do
    it "return decoded raw saml" do
      message = OneLogin::RubySaml::SamlMessage.new
      decoded_raw = message.send(:decode_raw_saml, logout_request_deflated_base64)
      assert logout_request_xml, decoded_raw
    end

    it "return encoded raw saml" do
      settings = OneLogin::RubySaml::Settings.new
      settings.compress_request = true
      message = OneLogin::RubySaml::SamlMessage.new
      encoded_raw = message.send(:encode_raw_saml, logout_request_xml, settings)
      assert logout_request_deflated_base64, encoded_raw

      settings2 = OneLogin::RubySaml::Settings.new
      settings2.compress_request = false
      message2 = OneLogin::RubySaml::SamlMessage.new
      deflated2 = message2.send(:deflate, logout_request_deflated_base64)
      encoded_raw2 = message.send(:encode_raw_saml, deflated2, settings)
      assert logout_request_deflated_base64, encoded_raw2
    end

    it "return decoded string" do
      message = OneLogin::RubySaml::SamlMessage.new
      decoded = message.send(:decode, response_document)
      assert response_document_xml, decoded

      message2 = OneLogin::RubySaml::SamlMessage.new
      decoded2 = message2.send(:decode, logout_request_base64)
      assert logout_request_xml, decoded2
    end

    it "return encoded string" do
      message = OneLogin::RubySaml::SamlMessage.new
      encoded = message.send(:encode, response_document_xml)
      assert response_document, encoded

      message2 = OneLogin::RubySaml::SamlMessage.new
      encoded2 = message2.send(:encode, logout_request_xml)
      assert logout_request_base64, encoded2
    end

    it "return deflated string" do
      message = OneLogin::RubySaml::SamlMessage.new
      deflated = message.send(:deflate, logout_request_xml)
      encoded_deflated = message.send(:encode, deflated)
      assert logout_request_deflated_base64, encoded_deflated
    end

    it "return inflated string" do
      message = OneLogin::RubySaml::SamlMessage.new
      decoded = message.send(:decode, logout_request_deflated_base64)
      decoded_inflated = message.send(:inflate, decoded)
      assert response_document_xml, decoded_inflated
    end
  end
end
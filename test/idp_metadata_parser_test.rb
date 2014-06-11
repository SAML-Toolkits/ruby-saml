require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'net/http'
require 'net/https'

class IdpMetadataParserTest < Test::Unit::TestCase

  class MockResponse
    attr_accessor :body
  end

  context "parsing an IdP descriptor file" do
    should "extract settings details from xml" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

      settings = idp_metadata_parser.parse(idp_metadata)

      assert_equal "https://example.hello.com/access/saml/login", settings.idp_sso_target_url
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
      assert_equal "https://example.hello.com/access/saml/logout", settings.idp_slo_target_url
    end
  end

  context "download and parse IdP descriptor file" do
    setup do
      mock_response = MockResponse.new
      mock_response.body = idp_metadata
      @url = "https://example.com"
      uri = URI(@url)

      @http = Net::HTTP.new(uri.host, uri.port)
      Net::HTTP.expects(:new).returns(@http)
      @http.expects(:request).returns(mock_response)
    end


    should "extract settings from remote xml" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      settings = idp_metadata_parser.parse_remote(@url)

      assert_equal "https://example.hello.com/access/saml/login", settings.idp_sso_target_url
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
      assert_equal "https://example.hello.com/access/saml/logout", settings.idp_slo_target_url
      assert_equal OpenSSL::SSL::VERIFY_PEER, @http.verify_mode
    end

    should "accept self signed certificate if insturcted" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      settings = idp_metadata_parser.parse_remote(@url, false)

      assert_equal OpenSSL::SSL::VERIFY_NONE, @http.verify_mode
    end
  end

end

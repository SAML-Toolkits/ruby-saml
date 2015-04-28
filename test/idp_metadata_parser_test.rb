require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/idp_metadata_parser'

class IdpMetadataParserTest < Minitest::Test

  class MockResponse
    attr_accessor :body
  end

  describe "IdP Metadata Parser Tests" do

    let(:mock_response) { MockResponse.new }

    describe "parsing an IdP descriptor file" do
      it "extract settings details from xml" do
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

        settings = idp_metadata_parser.parse(idp_metadata_https)

        assert_equal "https://example.hello.com/access/saml/idp.xml", settings.idp_entity_id
        assert_equal "https://example.hello.com/access/saml/login", settings.idp_sso_target_url
        assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
        assert_equal "https://example.hello.com/access/saml/logout", settings.idp_slo_target_url
        assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
      end
    end

    describe "download and parse IdP descriptor file (HTTPS)" do

      let(:https_url) { "https://example.com" }

      before do
        mock_response.body = idp_metadata_https        
        uri = URI.parse(https_url)
        @https_net = Net::HTTP.new(uri.host, uri.port)
        Net::HTTP.expects(:new).returns(@https_net)
        @https_net.expects(:request).returns(mock_response)
      end


      it "extract settings from remote xml" do
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
        settings = idp_metadata_parser.parse_remote(https_url)

        assert_equal "https://example.hello.com/access/saml/idp.xml", settings.idp_entity_id
        assert_equal "https://example.hello.com/access/saml/login", settings.idp_sso_target_url
        assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
        assert_equal "https://example.hello.com/access/saml/logout", settings.idp_slo_target_url
        assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
        assert_equal OpenSSL::SSL::VERIFY_PEER, @https_net.verify_mode
      end

      it "accept self signed certificate if insturcted" do
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
        settings = idp_metadata_parser.parse_remote(https_url, false)
        assert_equal OpenSSL::SSL::VERIFY_NONE, @https_net.verify_mode
      end
    end

    describe "download and parse IdP descriptor file (HTTP)" do

      let(:http_url) { "http://example.com" }

      before do
        mock_response.body = idp_metadata_http
        uri = URI.parse(http_url)
        @http_net = Net::HTTP.new(uri.host, uri.port)
        Net::HTTP.expects(:new).returns(@http_net)
        @http_net.expects(:request).returns(mock_response)
      end

      it "extract settings from remote xml [Requires internet access]" do
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
        settings = idp_metadata_parser.parse_remote(http_url)

        assert_equal "http://example.hello.com/access/saml/login", settings.idp_sso_target_url
        assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
        assert_equal "http://example.hello.com/access/saml/logout", settings.idp_slo_target_url
        refute_equal OpenSSL::SSL::VERIFY_PEER, @http_net.verify_mode
      end

      it "accept self signed certificate if instructed [Requires internet access]" do
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
        settings = idp_metadata_parser.parse_remote(http_url, false)
        refute_equal OpenSSL::SSL::VERIFY_NONE, @http_net.verify_mode
      end
    end
  end
end

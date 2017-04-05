require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/idp_metadata_parser'

class IdpMetadataParserTest < Minitest::Test
  class MockSuccessResponse < Net::HTTPSuccess
    # override parent's initialize
    def initialize; end

    attr_accessor :body
  end

  class MockFailureResponse < Net::HTTPNotFound
    # override parent's initialize
    def initialize; end

    attr_accessor :body
  end

  describe "parsing an IdP descriptor file" do
    it "extract settings details from xml" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

      settings = idp_metadata_parser.parse(idp_metadata)

      assert_equal "https://hello.example.com/access/saml/idp.xml", settings.idp_entity_id
      assert_equal "https://hello.example.com/access/saml/login", settings.idp_sso_target_url
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_target_url
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
      assert_equal ["AuthToken", "SSOStartPage"], settings.idp_attribute_names
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
    end

    it "extract certificate from md:KeyDescriptor[@use='signing']" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = read_response("idp_descriptor.xml")
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
    end

    it "extract certificate from md:KeyDescriptor[@use='encryption']" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = read_response("idp_descriptor.xml")
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
    end

    it "extract certificate from md:KeyDescriptor" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = read_response("idp_descriptor.xml")
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      idp_metadata = idp_metadata.sub('<md:KeyDescriptor use="encryption">', '<md:KeyDescriptor>')
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
    end

    it "uses settings options as hash for overrides" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = read_response("idp_descriptor.xml")
      settings = idp_metadata_parser.parse(idp_metadata, {
        :settings => {
          :security => {
            :digest_method => XMLSecurity::Document::SHA256,
            :signature_method => XMLSecurity::Document::RSA_SHA256
          }
        }
      })
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
      assert_equal XMLSecurity::Document::SHA256, settings.security[:digest_method]
      assert_equal XMLSecurity::Document::RSA_SHA256, settings.security[:signature_method]
    end

  end

  describe "download and parse IdP descriptor file" do
    before do
      mock_response = MockSuccessResponse.new
      mock_response.body = idp_metadata
      @url = "https://example.com"
      uri = URI(@url)

      @http = Net::HTTP.new(uri.host, uri.port)
      Net::HTTP.expects(:new).returns(@http)
      @http.expects(:request).returns(mock_response)
    end

    it "extract settings from remote xml" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      settings = idp_metadata_parser.parse_remote(@url)

      assert_equal "https://hello.example.com/access/saml/idp.xml", settings.idp_entity_id
      assert_equal "https://hello.example.com/access/saml/login", settings.idp_sso_target_url
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_target_url
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
      assert_equal ["AuthToken", "SSOStartPage"], settings.idp_attribute_names
      assert_equal OpenSSL::SSL::VERIFY_PEER, @http.verify_mode
    end

    it "accept self signed certificate if insturcted" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata_parser.parse_remote(@url, false)

      assert_equal OpenSSL::SSL::VERIFY_NONE, @http.verify_mode
    end
  end

  describe "download failure cases" do
    it "raises an exception when the url has no scheme" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

      exception = assert_raises(ArgumentError) do
        idp_metadata_parser.parse_remote("blahblah")
      end

      assert_equal("url must begin with http or https", exception.message)
    end

    it "raises an exception when unable to download metadata" do
      mock_response = MockFailureResponse.new
      @url = "https://example.com"
      uri = URI(@url)

      @http = Net::HTTP.new(uri.host, uri.port)
      Net::HTTP.expects(:new).returns(@http)
      @http.expects(:request).returns(mock_response)

      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

      exception = assert_raises(OneLogin::RubySaml::HttpError) do
        idp_metadata_parser.parse_remote("https://hello.example.com/access/saml/idp.xml")
      end

      assert_match("Failed to fetch idp metadata", exception.message)
    end
  end

  describe "parsing metadata with many entity descriptors" do
    before do
      @idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      @idp_metadata = read_response("idp_multiple_descriptors.xml")
      @settings = @idp_metadata_parser.parse(@idp_metadata)
    end

    it "should find first descriptor" do
      assert_equal "https://foo.example.com/access/saml/idp.xml", @settings.idp_entity_id
    end

    it "should find named descriptor" do
      entity_id = "https://bar.example.com/access/saml/idp.xml"
      settings = @idp_metadata_parser.parse(
        @idp_metadata, :entity_id => entity_id
      )
      assert_equal entity_id, settings.idp_entity_id
    end

    it "should retreive data" do
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", @settings.name_identifier_format
      assert_equal "https://hello.example.com/access/saml/login", @settings.idp_sso_target_url
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", @settings.idp_cert_fingerprint
      assert_equal "https://hello.example.com/access/saml/logout", @settings.idp_slo_target_url
      assert_equal ["AuthToken", "SSOStartPage"], @settings.idp_attribute_names
    end
  end
end

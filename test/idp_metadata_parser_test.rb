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

      settings = idp_metadata_parser.parse(idp_metadata_descriptor)

      assert_equal "https://hello.example.com/access/saml/idp.xml", settings.idp_entity_id
      assert_equal "https://hello.example.com/access/saml/login", settings.idp_sso_target_url
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_target_url
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
      assert_equal ["AuthToken", "SSOStartPage"], settings.idp_attribute_names
    end

    it "extract certificate from md:KeyDescriptor[@use='signing']" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
    end

    it "extract certificate from md:KeyDescriptor[@use='encryption']" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
    end

    it "extract certificate from md:KeyDescriptor" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      idp_metadata = idp_metadata.sub('<md:KeyDescriptor use="encryption">', '<md:KeyDescriptor>')
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
    end

    it "extract SSO endpoint with no specific binding, it takes the first" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "https://idp.example.com/idp/profile/Shibboleth/SSO", settings.idp_sso_target_url
    end

    it "extract SSO endpoint with specific binding" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      options = {}
      options[:sso_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/POST/SSO", settings.idp_sso_target_url

      options[:sso_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", settings.idp_sso_target_url

      options[:sso_binding] = ['invalid_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", settings.idp_sso_target_url      
    end

    it "uses settings options as hash for overrides" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
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

    it "merges results into given settings object" do
      settings = OneLogin::RubySaml::Settings.new(:security => {
        :digest_method => XMLSecurity::Document::SHA256,
        :signature_method => XMLSecurity::Document::RSA_SHA256
      })

      OneLogin::RubySaml::IdpMetadataParser.new.parse(idp_metadata_descriptor, :settings => settings)

      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
      assert_equal XMLSecurity::Document::SHA256, settings.security[:digest_method]
      assert_equal XMLSecurity::Document::RSA_SHA256, settings.security[:signature_method]
    end
  end

  describe "parsing an IdP descriptor file into an Hash" do
    it "extract settings details from xml" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

      metadata = idp_metadata_parser.parse_to_hash(idp_metadata_descriptor)

      assert_equal "https://hello.example.com/access/saml/idp.xml", metadata[:idp_entity_id]
      assert_equal "https://hello.example.com/access/saml/login", metadata[:idp_sso_target_url]
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", metadata[:idp_cert_fingerprint]
      assert_equal "https://hello.example.com/access/saml/logout", metadata[:idp_slo_target_url]
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", metadata[:name_identifier_format]
      assert_equal ["AuthToken", "SSOStartPage"], metadata[:idp_attribute_names]
    end

    it "extract certificate from md:KeyDescriptor[@use='signing']" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      metadata = idp_metadata_parser.parse_to_hash(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", metadata[:idp_cert_fingerprint]
    end

    it "extract certificate from md:KeyDescriptor[@use='encryption']" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", parsed_metadata[:idp_cert_fingerprint]
    end

    it "extract certificate from md:KeyDescriptor" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      idp_metadata = idp_metadata.sub('<md:KeyDescriptor use="encryption">', '<md:KeyDescriptor>')
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata)
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", parsed_metadata[:idp_cert_fingerprint]
    end

    it "extract SSO endpoint with no specific binding, it takes the first" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      metadata = idp_metadata_parser.parse_to_hash(idp_metadata)
      assert_equal "https://idp.example.com/idp/profile/Shibboleth/SSO", metadata[:idp_sso_target_url]
    end

    it "extract SSO endpoint with specific binding" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      options = {}
      options[:sso_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/POST/SSO", parsed_metadata[:idp_sso_target_url]

      options[:sso_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", parsed_metadata[:idp_sso_target_url]

      options[:sso_binding] = ['invalid_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", parsed_metadata[:idp_sso_target_url]
    end

    it "ignores a given :settings hash" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata, {
        :settings => {
          :security => {
            :digest_method => XMLSecurity::Document::SHA256,
            :signature_method => XMLSecurity::Document::RSA_SHA256
          }
        }
      })
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", parsed_metadata[:idp_cert_fingerprint]
      assert_nil parsed_metadata[:security]
    end
  end

  describe "parsing an IdP descriptor file with multiple signing certs" do
    it "extract settings details from xml" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

      settings = idp_metadata_parser.parse(idp_metadata_descriptor2)

      assert_equal "https://hello.example.com/access/saml/idp.xml", settings.idp_entity_id
      assert_equal "https://hello.example.com/access/saml/login", settings.idp_sso_target_url
      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_target_url
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
      assert_equal ["AuthToken", "SSOStartPage"], settings.idp_attribute_names

      assert_nil settings.idp_cert_fingerprint
      assert_nil settings.idp_cert
      assert_equal 2, settings.idp_cert_multi.size
      assert settings.idp_cert_multi.key?("signing")
      assert_equal 2, settings.idp_cert_multi["signing"].size
      assert settings.idp_cert_multi.key?("encryption")
      assert_equal 1, settings.idp_cert_multi["encryption"].size
    end
  end

  describe "download and parse IdP descriptor file" do
    before do
      mock_response = MockSuccessResponse.new
      mock_response.body = idp_metadata_descriptor
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

  describe "download and parse IdP descriptor file into an Hash" do
    before do
      mock_response = MockSuccessResponse.new
      mock_response.body = idp_metadata_descriptor
      @url = "https://example.com"
      uri = URI(@url)

      @http = Net::HTTP.new(uri.host, uri.port)
      Net::HTTP.expects(:new).returns(@http)
      @http.expects(:request).returns(mock_response)
    end

    it "extract settings from remote xml" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      parsed_metadata = idp_metadata_parser.parse_remote_to_hash(@url)

      assert_equal "https://hello.example.com/access/saml/idp.xml", parsed_metadata[:idp_entity_id]
      assert_equal "https://hello.example.com/access/saml/login", parsed_metadata[:idp_sso_target_url]
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", parsed_metadata[:idp_cert_fingerprint]
      assert_equal "https://hello.example.com/access/saml/logout", parsed_metadata[:idp_slo_target_url]
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", parsed_metadata[:name_identifier_format]
      assert_equal ["AuthToken", "SSOStartPage"], parsed_metadata[:idp_attribute_names]
      assert_equal OpenSSL::SSL::VERIFY_PEER, @http.verify_mode
    end

    it "accept self signed certificate if insturcted" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata_parser.parse_remote_to_hash(@url, false)

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
      @idp_metadata = idp_metadata_multiple_descriptors
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

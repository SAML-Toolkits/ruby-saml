require_relative 'test_helper'

require 'ruby_saml/idp_metadata_parser'

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
      idp_metadata_parser = RubySaml::IdpMetadataParser.new

      settings = idp_metadata_parser.parse(idp_metadata_descriptor)

      assert_equal "https://hello.example.com/access/saml/idp.xml", settings.idp_entity_id
      assert_equal "https://hello.example.com/access/saml/login", settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_sso_service_binding
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", settings.idp_cert_fingerprint
      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_slo_service_binding
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
      assert_equal ["AuthToken", "SSOStartPage"], settings.idp_attribute_names
      assert_equal '2014-04-17T18:02:33.910Z', settings.valid_until
    end

    it "extract certificate from md:KeyDescriptor[@use='signing']" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", settings.idp_cert_fingerprint
    end

    it "extract certificate from md:KeyDescriptor[@use='encryption']" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", settings.idp_cert_fingerprint
    end

    it "extract certificate from md:KeyDescriptor" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      idp_metadata = idp_metadata.sub('<md:KeyDescriptor use="encryption">', '<md:KeyDescriptor>')
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", settings.idp_cert_fingerprint
    end

    it "extract SSO endpoint with no specific binding, it takes the first" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "https://idp.example.com/idp/profile/Shibboleth/SSO", settings.idp_sso_service_url
      assert_equal "urn:mace:shibboleth:1.0:profiles:AuthnRequest", settings.idp_sso_service_binding
    end

    it "extract SSO endpoint with specific binding as a String" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      options = {}
      options[:sso_binding] = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      options[:slo_binding] = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/POST/SSO", settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", settings.idp_sso_service_binding
      assert_nil settings.idp_slo_service_url

      options[:sso_binding] = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
      options[:slo_binding] = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_sso_service_binding
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SLO", settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_slo_service_binding
    end

    it "extract SSO endpoint with specific binding as an Array" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      options = {}
      options[:sso_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
      options[:slo_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/POST/SSO", settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", settings.idp_sso_service_binding
      assert_nil settings.idp_slo_service_url

      options[:sso_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      options[:slo_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_sso_service_binding
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SLO", settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_slo_service_binding

      options[:sso_binding] = ['invalid_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      options[:slo_binding] = ['invalid_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_sso_service_binding
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SLO", settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_slo_service_binding
    end

    it "extract NameIDFormat no specific priority, it takes the first" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      settings = idp_metadata_parser.parse(idp_metadata)
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
    end

    it "extract NameIDFormat specific priority as a String" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      options = {}
      options[:name_id_format] = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format

      options[:name_id_format] = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", settings.name_identifier_format

      options[:name_id_format] = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", settings.name_identifier_format
    end

    it "extract NameIDFormat specific priority as an Array" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      options = {}
      options[:name_id_format] = ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress']
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", settings.name_identifier_format

      options[:name_id_format] = ['invalid', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress']
      settings = idp_metadata_parser.parse(idp_metadata, options)
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", settings.name_identifier_format
    end

    it "uses settings options as hash for overrides" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      settings = idp_metadata_parser.parse(idp_metadata, {
        :settings => {
          :security => {
            :digest_method => RubySaml::XML::Document::SHA256,
            :signature_method => RubySaml::XML::Document::RSA_SHA256
          }
        }
      })
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", settings.idp_cert_fingerprint
      assert_equal RubySaml::XML::Document::SHA256, settings.security[:digest_method]
      assert_equal RubySaml::XML::Document::RSA_SHA256, settings.security[:signature_method]
    end

    it "merges results into given settings object" do
      settings = RubySaml::Settings.new(:security => {
        :digest_method => RubySaml::XML::Document::SHA256,
        :signature_method => RubySaml::XML::Document::RSA_SHA256
      })

      RubySaml::IdpMetadataParser.new.parse(idp_metadata_descriptor, :settings => settings)

      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", settings.idp_cert_fingerprint
      assert_equal RubySaml::XML::Document::SHA256, settings.security[:digest_method]
      assert_equal RubySaml::XML::Document::RSA_SHA256, settings.security[:signature_method]
    end
  end

  describe "parsing an IdP descriptor file into an Hash" do
    it "extract settings details from xml" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new

      metadata = idp_metadata_parser.parse_to_hash(idp_metadata_descriptor)

      assert_equal "https://hello.example.com/access/saml/idp.xml", metadata[:idp_entity_id]
      assert_equal "https://hello.example.com/access/saml/login", metadata[:idp_sso_service_url]
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", metadata[:idp_sso_service_binding]
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", metadata[:idp_cert_fingerprint]
      assert_equal "https://hello.example.com/access/saml/logout", metadata[:idp_slo_service_url]
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", metadata[:idp_slo_service_binding]
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", metadata[:name_identifier_format]
      assert_equal ["AuthToken", "SSOStartPage"], metadata[:idp_attribute_names]
      assert_equal '2014-04-17T18:02:33.910Z', metadata[:valid_until]
    end

    it "extract certificate from md:KeyDescriptor[@use='signing']" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      metadata = idp_metadata_parser.parse_to_hash(idp_metadata)
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", metadata[:idp_cert_fingerprint]
    end

    it "extract certificate from md:KeyDescriptor[@use='encryption']" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata)
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", parsed_metadata[:idp_cert_fingerprint]
    end

    it "extract certificate from md:KeyDescriptor" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      idp_metadata = idp_metadata.sub(/<md:KeyDescriptor use="signing">(.*?)<\/md:KeyDescriptor>/m, "")
      idp_metadata = idp_metadata.sub('<md:KeyDescriptor use="encryption">', '<md:KeyDescriptor>')
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata)
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", parsed_metadata[:idp_cert_fingerprint]
    end

    it "extract SSO endpoint with no specific binding, it takes the first" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      metadata = idp_metadata_parser.parse_to_hash(idp_metadata)
      assert_equal "https://idp.example.com/idp/profile/Shibboleth/SSO", metadata[:idp_sso_service_url]
      assert_equal "urn:mace:shibboleth:1.0:profiles:AuthnRequest", metadata[:idp_sso_service_binding]
    end

    it "extract SSO endpoint with specific binding" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor3
      options = {}
      options[:sso_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/POST/SSO", parsed_metadata[:idp_sso_service_url]
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", parsed_metadata[:idp_sso_service_binding]

      options[:sso_binding] = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", parsed_metadata[:idp_sso_service_url]
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", parsed_metadata[:idp_sso_service_binding]

      options[:sso_binding] = ['invalid_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata, options)
      assert_equal "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", parsed_metadata[:idp_sso_service_url]
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", parsed_metadata[:idp_sso_service_binding]
    end

    it "ignores a given :settings hash" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_descriptor
      parsed_metadata = idp_metadata_parser.parse_to_hash(idp_metadata, {
        :settings => {
          :security => {
            :digest_method => RubySaml::XML::Document::SHA256,
            :signature_method => RubySaml::XML::Document::RSA_SHA256
          }
        }
      })
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", parsed_metadata[:idp_cert_fingerprint]
      assert_nil parsed_metadata[:security]
    end

    it "can extract certificates multiple times in sequence" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata1 = idp_metadata_descriptor
      idp_metadata2 = idp_metadata_descriptor4
      metadata1 = idp_metadata_parser.parse_to_hash(idp_metadata1)
      metadata2 = idp_metadata_parser.parse_to_hash(idp_metadata2)

      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", metadata1[:idp_cert_fingerprint]
      assert_equal "E5:52:D9:2C:3C:DC:3D:09:5C:90:76:82:AB:B6:75:B4:92:92:2C:42:87:7E:18:EB:17:F3:1F:39:FE:9F:7C:6A", metadata2[:idp_cert_fingerprint]
    end
  end

  describe "parsing an IdP descriptor file with multiple signing certs" do
    it "extract settings details from xml" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new

      settings = idp_metadata_parser.parse(idp_metadata_descriptor2)

      assert_equal "https://hello.example.com/access/saml/idp.xml", settings.idp_entity_id
      assert_equal "https://hello.example.com/access/saml/login", settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_sso_service_binding
      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_slo_service_binding
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
      assert_equal ["AuthToken", "SSOStartPage"], settings.idp_attribute_names

      assert_nil settings.idp_cert_fingerprint
      assert_nil settings.idp_cert
      assert_equal 2, settings.idp_cert_multi.size
      assert settings.idp_cert_multi.key?(:signing)
      assert_equal 2, settings.idp_cert_multi[:signing].size
      assert settings.idp_cert_multi.key?(:encryption)
      assert_equal 1, settings.idp_cert_multi[:encryption].size
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
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      settings = idp_metadata_parser.parse_remote(@url)

      assert_equal "https://hello.example.com/access/saml/idp.xml", settings.idp_entity_id
      assert_equal "https://hello.example.com/access/saml/login", settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_sso_service_binding
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", settings.idp_cert_fingerprint
      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_slo_service_binding
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", settings.name_identifier_format
      assert_equal ["AuthToken", "SSOStartPage"], settings.idp_attribute_names
      assert_equal '2014-04-17T18:02:33.910Z', settings.valid_until
      assert_equal OpenSSL::SSL::VERIFY_PEER, @http.verify_mode
    end

    it "accept self signed certificate if insturcted" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
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
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      parsed_metadata = idp_metadata_parser.parse_remote_to_hash(@url)

      assert_equal "https://hello.example.com/access/saml/idp.xml", parsed_metadata[:idp_entity_id]
      assert_equal "https://hello.example.com/access/saml/login", parsed_metadata[:idp_sso_service_url]
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", parsed_metadata[:idp_sso_service_binding]
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", parsed_metadata[:idp_cert_fingerprint]
      assert_equal "https://hello.example.com/access/saml/logout", parsed_metadata[:idp_slo_service_url]
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", parsed_metadata[:idp_slo_service_binding]
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", parsed_metadata[:name_identifier_format]
      assert_equal ["AuthToken", "SSOStartPage"], parsed_metadata[:idp_attribute_names]
      assert_equal '2014-04-17T18:02:33.910Z', parsed_metadata[:valid_until]
      assert_equal OpenSSL::SSL::VERIFY_PEER, @http.verify_mode
    end

    it "accept self signed certificate if insturcted" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new
      idp_metadata_parser.parse_remote_to_hash(@url, false)

      assert_equal OpenSSL::SSL::VERIFY_NONE, @http.verify_mode
    end
  end

  describe "download failure cases" do
    it "raises an exception when the url has no scheme" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new

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

      idp_metadata_parser = RubySaml::IdpMetadataParser.new

      exception = assert_raises(RubySaml::HttpError) do
        idp_metadata_parser.parse_remote("https://hello.example.com/access/saml/idp.xml")
      end

      assert_match("Failed to fetch idp metadata", exception.message)
    end
  end

  describe "parsing metadata with and without ValidUntil and CacheDuration" do
    before do
      @idp_metadata_parser = RubySaml::IdpMetadataParser.new
    end

    it "if no ValidUntil or CacheDuration return nothing" do
      settings = @idp_metadata_parser.parse(idp_metadata_descriptor3)
      assert_nil settings.valid_until
    end

    it "if ValidUntil and not CacheDuration return ValidUntil value" do
      settings = @idp_metadata_parser.parse(idp_metadata_descriptor)
      assert_equal '2014-04-17T18:02:33.910Z', settings.valid_until
    end

    it "if no ValidUntil but CacheDuration return CacheDuration converted in ValidUntil" do
      Timecop.freeze(Time.parse("2020-01-02T10:02:33Z", Time.now.utc)) do
        settings = @idp_metadata_parser.parse(idp_metadata_descriptor5)
        assert_equal '2020-01-03T10:02:33Z', settings.valid_until
      end
    end

    it "if ValidUntil and CacheDuration return the sooner timestamp" do
      Timecop.freeze(Time.parse("2020-01-01T10:12:55Z", Time.now.utc)) do
        settings = @idp_metadata_parser.parse(idp_metadata_descriptor6)
        assert_equal '2020-01-03T10:12:55Z', settings.valid_until
      end

      Timecop.freeze(Time.parse("2020-01-01T10:12:55Z", Time.now.utc)) do
        settings = @idp_metadata_parser.parse(idp_metadata_descriptor6)
        assert_equal '2020-01-03T10:12:55Z', settings.valid_until
      end

      Timecop.freeze(Time.parse("2020-01-03T10:12:55Z", Time.now.utc)) do
        settings = @idp_metadata_parser.parse(idp_metadata_descriptor6)
        assert_equal '2020-01-04T18:02:33.910Z', settings.valid_until
      end
    end

  end

  describe "parsing metadata with many entity descriptors" do
    before do
      @idp_metadata_parser = RubySaml::IdpMetadataParser.new
      @idp_metadata = idp_metadata_multiple_descriptors2
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
      assert_equal "https://hello.example.com/access/saml/login", @settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.idp_sso_service_binding
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", @settings.idp_cert_fingerprint
      assert_equal "https://hello.example.com/access/saml/logout", @settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.idp_slo_service_binding
      assert_equal ["AuthToken", "SSOStartPage"], @settings.idp_attribute_names
      assert_equal '2014-04-17T18:02:33.910Z', @settings.valid_until
    end

    it "should handle multiple descriptors at once" do
      settings = @idp_metadata_parser.parse_to_array(@idp_metadata)
      assert_equal "https://foo.example.com/access/saml/idp.xml", settings.first[:idp_entity_id]
      assert_equal "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21", settings.first[:idp_cert_fingerprint]
      assert_equal '2014-04-17T18:02:33.910Z', settings.first[:valid_until]
      assert_equal "https://bar.example.com/access/saml/idp.xml", settings.last[:idp_entity_id]
      assert_equal "74:E4:FA:29:20:26:36:8A:72:5E:9D:CF:4F:8E:1F:DC:D4:CE:E2:3C:9D:6F:93:35:A1:A7:8A:4D:79:83:21:D0", settings.last[:idp_cert_fingerprint]
      assert_equal '2014-04-17T18:02:33.910Z', settings.last[:valid_until]
    end
  end

  describe "parsing metadata with no IDPSSODescriptor element" do
    before do
      @idp_metadata_parser = RubySaml::IdpMetadataParser.new
      @idp_metadata = no_idp_metadata_descriptor
    end

    it "raise due no IDPSSODescriptor element" do
        assert_raises(ArgumentError) { @idp_metadata_parser.parse(@idp_metadata) }
    end
  end

  describe "parsing metadata with IDPSSODescriptor with multiple certs" do
    before do
      @idp_metadata_parser = RubySaml::IdpMetadataParser.new
      @idp_metadata = idp_metadata_multiple_certs
      @settings = @idp_metadata_parser.parse(@idp_metadata)
    end

    it "should return a idp_cert_multi and no idp_cert and no idp_cert_fingerprint" do
      assert_nil @settings.idp_cert
      assert_nil @settings.idp_cert_fingerprint

      expected_multi_cert = {}
      expected_multi_cert[:signing] = ["MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEF
BQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJj
aWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwW
T25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUy
MjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChz
Z2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNV
BAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo
3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRw
tnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xx
VRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5
L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t
1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/
BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCB
pIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYD
VQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQL
DAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaC
FD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0B
AQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXM
GI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65c
hjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIB
vlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37
MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZ
WQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw==", "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xNzA0MTUxNjMzMThaFw0xODA0MTUxNjMzMThaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6GLkl5lDUZdHNDAojp5i24OoPlqrt5TGXJIPqAZYT1hQvJW5nv17MFDHrjmtEnmW4ACKEy0fAX80QWIcHunZSkbEGHb+NG/6oTi5RipXMvmHnfFnPJJ0AdtiLiPE478CV856gXekV4Xx5u3KrylcOgkpYsp0GMIQBDzleMUXlYQIDAQABo1AwTjAdBgNVHQ4EFgQUnP8vlYPGPL2n6ZzDYij2kMDC8wMwHwYDVR0jBBgwFoAUnP8vlYPGPL2n6ZzDYij2kMDC8wMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQAlQGAl+b8Cpot1g+65lLLjVoY7APJPWLW0klKQNlMU0s4MU+71Y3ExUEOXDAZgKcFoavb1fEOGMwEf38NaJAy1e/l6VNuixXShffq20ymqHQxOG0q8ujeNkgZF9k6XDfn/QZ3AD0o/IrCT7UMc/0QsfgIjWYxwCvp2syApc5CYfQ=="]
      expected_multi_cert[:encryption] = ["MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEF
BQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJj
aWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwW
T25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUy
MjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChz
Z2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNV
BAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo
3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRw
tnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xx
VRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5
L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t
1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/
BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCB
pIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYD
VQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQL
DAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaC
FD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0B
AQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXM
GI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65c
hjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIB
vlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37
MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZ
WQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="]

      assert_equal expected_multi_cert, @settings.idp_cert_multi
      assert_equal "https://idp.examle.com/saml/metadata", @settings.idp_entity_id
      assert_equal "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", @settings.name_identifier_format
      assert_equal "https://idp.examle.com/saml/sso", @settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.idp_sso_service_binding
      assert_equal "https://idp.examle.com/saml/slo", @settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.idp_slo_service_binding
    end
  end

  describe "parsing metadata with IDPSSODescriptor with multiple signing certs" do
    before do
      @idp_metadata_parser = RubySaml::IdpMetadataParser.new
      @idp_metadata = idp_metadata_multiple_signing_certs
      @settings = @idp_metadata_parser.parse(@idp_metadata)
    end

    it "should return a idp_cert_multi and no idp_cert and no idp_cert_fingerprint" do
      assert_nil @settings.idp_cert
      assert_nil @settings.idp_cert_fingerprint

      expected_multi_cert = {}
      expected_multi_cert[:signing] = ["MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEF
BQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJj
aWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwW
T25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUy
MjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChz
Z2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNV
BAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo
3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRw
tnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xx
VRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5
L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t
1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/
BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCB
pIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYD
VQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQL
DAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaC
FD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0B
AQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXM
GI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65c
hjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIB
vlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37
MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZ
WQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw==", "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xNzA0MTUxNjMzMThaFw0xODA0MTUxNjMzMThaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6GLkl5lDUZdHNDAojp5i24OoPlqrt5TGXJIPqAZYT1hQvJW5nv17MFDHrjmtEnmW4ACKEy0fAX80QWIcHunZSkbEGHb+NG/6oTi5RipXMvmHnfFnPJJ0AdtiLiPE478CV856gXekV4Xx5u3KrylcOgkpYsp0GMIQBDzleMUXlYQIDAQABo1AwTjAdBgNVHQ4EFgQUnP8vlYPGPL2n6ZzDYij2kMDC8wMwHwYDVR0jBBgwFoAUnP8vlYPGPL2n6ZzDYij2kMDC8wMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQAlQGAl+b8Cpot1g+65lLLjVoY7APJPWLW0klKQNlMU0s4MU+71Y3ExUEOXDAZgKcFoavb1fEOGMwEf38NaJAy1e/l6VNuixXShffq20ymqHQxOG0q8ujeNkgZF9k6XDfn/QZ3AD0o/IrCT7UMc/0QsfgIjWYxwCvp2syApc5CYfQ==","LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURxekNDQXhTZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBRENCaGpFTE1Ba0dBMVVFQmhNQ1FWVXgKRERBS0JnTlZCQWdUQTA1VFZ6RVBNQTBHQTFVRUJ4TUdVM2xrYm1WNU1Rd3dDZ1lEVlFRS0RBTlFTVlF4Q1RBSApCZ05WQkFzTUFERVlNQllHQTFVRUF3d1BiR0YzY21WdVkyVndhWFF1WTI5dE1TVXdJd1lKS29aSWh2Y05BUWtCCkRCWnNZWGR5Wlc1alpTNXdhWFJBWjIxaGFXd3VZMjl0TUI0WERURXlNRFF4T1RJeU5UUXhPRm9YRFRNeU1EUXgKTkRJeU5UUXhPRm93Z1lZeEN6QUpCZ05WQkFZVEFrRlZNUXd3Q2dZRFZRUUlFd05PVTFjeER6QU5CZ05WQkFjVApCbE41Wkc1bGVURU1NQW9HQTFVRUNnd0RVRWxVTVFrd0J3WURWUVFMREFBeEdEQVdCZ05WQkFNTUQyeGhkM0psCmJtTmxjR2wwTG1OdmJURWxNQ01HQ1NxR1NJYjNEUUVKQVF3V2JHRjNjbVZ1WTJVdWNHbDBRR2R0WVdsc0xtTnYKYlRDQm56QU5CZ2txaGtpRzl3MEJBUUVGQUFPQmpRQXdnWWtDZ1lFQXFqaWUzUjJvaStwRGFldndJeXMvbWJVVApubkdsa3h0ZGlrcnExMXZleHd4SmlQTmhtaHFSVzNtVXVKRXpsbElkVkw2RW14R1lUcXBxZjkzSGxoa3NhZUowCjhVZ2pQOVVtTVlyaFZKdTFqY0ZXVjdmei9yKzIxL2F3VG5EVjlzTVlRcXVJUllZeTdiRzByMU9iaXdkb3ZudGsKN2dGSTA2WjB2WmFjREU1Ym9xVUNBd0VBQWFPQ0FTVXdnZ0VoTUFrR0ExVWRFd1FDTUFBd0N3WURWUjBQQkFRRApBZ1VnTUIwR0ExVWREZ1FXQkJTUk9OOEdKOG8rOGpnRnRqa3R3WmRxeDZCUnlUQVRCZ05WSFNVRUREQUtCZ2dyCkJnRUZCUWNEQVRBZEJnbGdoa2dCaHZoQ0FRMEVFQllPVkdWemRDQllOVEE1SUdObGNuUXdnYk1HQTFVZEl3U0IKcXpDQnFJQVVrVGpmQmlmS1B2STRCYlk1TGNHWGFzZWdVY21oZ1l5a2dZa3dnWVl4Q3pBSkJnTlZCQVlUQWtGVgpNUXd3Q2dZRFZRUUlFd05PVTFjeER6QU5CZ05WQkFjVEJsTjVaRzVsZVRFTU1Bb0dBMVVFQ2d3RFVFbFVNUWt3CkJ3WURWUVFMREFBeEdEQVdCZ05WQkFNTUQyeGhkM0psYm1ObGNHbDBMbU52YlRFbE1DTUdDU3FHU0liM0RRRUoKQVF3V2JHRjNjbVZ1WTJVdWNHbDBRR2R0WVdsc0xtTnZiWUlCQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9CZ1FDRQpUQWVKVERTQVc2ejFVRlRWN1FyZWg0VUxGT1JhajkrZUN1RjNLV0RIYyswSVFDajlyZG5ERzRRL3dmNy9yYVEwCkpuUFFDU0NkclBMSmV5b1BIN1FhVHdvYUY3ZHpWdzRMQ3N5TkpURld4NGNNNTBWdzZSNWZET2dpQzhic2ZmUzgKQkptb3VscnJaRE5OVmpHOG1XNmNMeHJZdlZRT3JSVmVjQ0ZJZ3NzQ2JBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]

      assert_equal expected_multi_cert, @settings.idp_cert_multi
      assert_equal "https://idp.examle.com/saml/metadata", @settings.idp_entity_id
      assert_equal "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", @settings.name_identifier_format
      assert_equal "https://idp.examle.com/saml/sso", @settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.idp_sso_service_binding
      assert_equal "https://idp.examle.com/saml/slo", @settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.idp_slo_service_binding
    end
  end

  describe "parsing metadata with IDPSSODescriptor with same signature cert and encrypt cert" do
    before do
      @idp_metadata_parser = RubySaml::IdpMetadataParser.new
      @idp_metadata = idp_metadata_same_sign_and_encrypt_cert
      @settings = @idp_metadata_parser.parse(@idp_metadata)
    end

    let(:expected_cert) do
      "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYD
VQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2
MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
DApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9u
ZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z
0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sT
gf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0m
Tr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SF
zRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJ
UAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwG
A1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNV
HSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREw
DwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAO
BgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHu
AuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcV
gG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJ
sTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClP
TbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWu
QOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh78
1sE="
    end

    it "should return idp_cert and idp_cert_fingerprint and no idp_cert_multi" do
      assert_equal(expected_cert, @settings.idp_cert)
      assert_equal("46:E3:68:F4:ED:61:43:2B:EC:36:E3:99:E9:03:4B:99:E5:B3:58:EF:A9:A9:00:FC:2D:C8:7C:14:C6:60:E3:8F", @settings.idp_cert_fingerprint)
      assert_equal({ :signing => [expected_cert], :encryption => [expected_cert] }, @settings.idp_cert_multi)
      assert_equal("https://app.onelogin.com/saml/metadata/383123", @settings.idp_entity_id)
      assert_equal("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", @settings.name_identifier_format)
      assert_equal("https://app.onelogin.com/trust/saml2/http-post/sso/383123", @settings.idp_sso_service_url)
      assert_nil(@settings.idp_slo_service_url)
      # TODO: next line can be changed to `assert_nil @settings.idp_slo_service_binding` after :embed_sign is removed.
      assert_nil(@settings.instance_variable_get('@idp_slo_service_binding'))
    end
  end

  describe "parsing metadata with IDPSSODescriptor with different signature cert and encrypt cert" do
    before do
      @idp_metadata_parser = RubySaml::IdpMetadataParser.new
      @idp_metadata = idp_metadata_different_sign_and_encrypt_cert
      @settings = @idp_metadata_parser.parse(@idp_metadata)
    end

    it "should return a idp_cert_multi and no idp_cert and no idp_cert_fingerprint" do
      assert_nil @settings.idp_cert
      assert_nil @settings.idp_cert_fingerprint

      expected_multi_cert = {}
      expected_multi_cert[:signing] = ["MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYD
VQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2
MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
DApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9u
ZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z
0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sT
gf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0m
Tr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SF
zRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJ
UAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwG
A1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNV
HSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREw
DwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAO
BgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHu
AuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcV
gG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJ
sTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClP
TbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWu
QOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh78
1sE="]
      expected_multi_cert[:encryption] = ["MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEF
BQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJj
aWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwW
T25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUy
MjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChz
Z2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNV
BAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo
3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRw
tnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xx
VRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5
L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t
1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/
BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCB
pIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYD
VQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQL
DAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaC
FD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0B
AQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXM
GI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65c
hjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIB
vlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37
MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZ
WQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="]

      assert_equal expected_multi_cert, @settings.idp_cert_multi
      assert_equal "https://app.onelogin.com/saml/metadata/383123", @settings.idp_entity_id
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", @settings.name_identifier_format
      assert_equal "https://app.onelogin.com/trust/saml2/http-post/sso/383123", @settings.idp_sso_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.idp_sso_service_binding
      assert_nil @settings.idp_slo_service_url
      # TODO: next line can be changed to `assert_nil @settings.idp_slo_service_binding` after :embed_sign is removed.
      assert_nil @settings.instance_variable_get('@idp_slo_service_binding')
    end
  end

  describe "metadata with different singlelogout response location" do
    it "should return the responselocation if it exists" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new

      settings = idp_metadata_parser.parse(idp_different_slo_response_location)

      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_slo_service_binding
      assert_equal "https://hello.example.com/access/saml/logout/return", settings.idp_slo_response_service_url
    end

    it "should set the responselocation to nil if it doesnt exist" do
      idp_metadata_parser = RubySaml::IdpMetadataParser.new

      settings = idp_metadata_parser.parse(idp_without_slo_response_location)

      assert_equal "https://hello.example.com/access/saml/logout", settings.idp_slo_service_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.idp_slo_service_binding
      assert_nil settings.idp_slo_response_service_url
    end
  end
end

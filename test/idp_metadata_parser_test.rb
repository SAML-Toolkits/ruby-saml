require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class IdpMetadataParserTest < Test::Unit::TestCase

  context "parsing an IdP descriptor file" do
    should "extract settings details from xml" do
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

      settings = idp_metadata_parser.parse(idp_metadata)

      assert_equal "https://example.hello.com/access/saml/login", settings.idp_sso_target_url
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", settings.protocol_binding
      assert_equal "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72", settings.idp_cert_fingerprint
      assert_equal "https://example.hello.com/access/saml/logout", settings.idp_slo_target_url
      assert_equal "https://example.hello.com/access/saml/idp.xml", settings.entity_id
    end
  end

end

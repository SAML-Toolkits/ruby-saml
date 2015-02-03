require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class MetadataTest < Minitest::Test

  describe 'Metadata' do
    def setup
      @settings = OneLogin::RubySaml::Settings.new
      @settings.issuer = "https://example.com"
      @settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      @settings.assertion_consumer_service_url = "https://foo.example/saml/consume"
      @settings.security[:authn_requests_signed] = false
    end

    it "generates Service Provider Metadata with X509Certificate" do
      @settings.security[:authn_requests_signed] = true
      @settings.certificate = ruby_saml_cert_text

      xml_text = OneLogin::RubySaml::Metadata.new.generate(@settings)

      # assert xml_text can be parsed into an xml doc
      xml_doc = REXML::Document.new(xml_text)

      spsso_descriptor = REXML::XPath.first(xml_doc, "//md:SPSSODescriptor")
      assert_equal "true", spsso_descriptor.attribute("AuthnRequestsSigned").value

      cert_node = REXML::XPath.first(xml_doc, "//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", {
        "md" => "urn:oasis:names:tc:SAML:2.0:metadata",
        "ds" => "http://www.w3.org/2000/09/xmldsig#"
      })
      cert_text = cert_node.text
      cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert_text))
      assert_equal ruby_saml_cert.to_der, cert.to_der
    end

    it "generates Service Provider Metadata" do
      settings = OneLogin::RubySaml::Settings.new
      settings.issuer = "https://example.com"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      settings.assertion_consumer_service_url = "https://foo.example/saml/consume"
      settings.security[:authn_requests_signed] = false

      xml_text = OneLogin::RubySaml::Metadata.new.generate(settings)

      # assert correct xml declaration
      start = "<?xml version='1.0' encoding='UTF-8'?>\n<md:EntityDescriptor"
      assert xml_text[0..start.length-1] == start

      # assert xml_text can be parsed into an xml doc
      xml_doc = REXML::Document.new(xml_text)

      assert_equal "https://example.com", REXML::XPath.first(xml_doc, "//md:EntityDescriptor").attribute("entityID").value

      spsso_descriptor = REXML::XPath.first(xml_doc, "//md:SPSSODescriptor")
      assert_equal "urn:oasis:names:tc:SAML:2.0:protocol", spsso_descriptor.attribute("protocolSupportEnumeration").value
      assert_equal "false", spsso_descriptor.attribute("AuthnRequestsSigned").value
      assert_equal "false", spsso_descriptor.attribute("WantAssertionsSigned").value

      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", REXML::XPath.first(xml_doc, "//md:NameIDFormat").text.strip

      acs = REXML::XPath.first(xml_doc, "//md:AssertionConsumerService")
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs.attribute("Binding").value
      assert_equal "https://foo.example/saml/consume", acs.attribute("Location").value
    end

    it "generates attribute service if configured" do
      settings = OneLogin::RubySaml::Settings.new
      settings.issuer = "https://example.com"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      settings.assertion_consumer_service_url = "https://foo.example/saml/consume"
      settings.attribute_consuming_service.configure do
        service_name "Test Service"
        add_attribute(:name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name", :attribute_value => "Attribute Value")
      end

      xml_text = OneLogin::RubySaml::Metadata.new.generate(settings)
      xml_doc = REXML::Document.new(xml_text)
      acs = REXML::XPath.first(xml_doc, "//md:AttributeConsumingService")
      assert_equal "true", acs.attribute("isDefault").value
      assert_equal "1", acs.attribute("index").value
      assert_equal REXML::XPath.first(xml_doc, "//md:ServiceName").text.strip, "Test Service"
      req_attr = REXML::XPath.first(xml_doc, "//md:RequestedAttribute")
      assert_equal "Name", req_attr.attribute("Name").value
      assert_equal "Name Format", req_attr.attribute("NameFormat").value
      assert_equal "Friendly Name", req_attr.attribute("FriendlyName").value
      assert_equal "Attribute Value", REXML::XPath.first(xml_doc, "//md:AttributeValue").text.strip
    end
  end
end

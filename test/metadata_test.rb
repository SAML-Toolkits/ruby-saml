require 'test_helper'

class MetadataTest < Test::Unit::TestCase

  should "should generate Service Provider Metadata" do
    settings = Onelogin::Saml::Settings.new
    settings.issuer = "https://example.com"
    settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    settings.assertion_consumer_service_url = "https://foo.example/saml/consume"

    xml_text = Onelogin::Saml::Metadata.new.generate(settings)

    # assert correct xml declaration
    start = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n<md:EntityDescriptor"
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

end
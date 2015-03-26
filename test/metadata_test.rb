require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/metadata'

class MetadataTest < Minitest::Test

  describe 'Metadata' do
    let(:settings)          { OneLogin::RubySaml::Settings.new }
    let(:xml_text)          { OneLogin::RubySaml::Metadata.new.generate(settings, false) }
    let(:xml_doc)           { REXML::Document.new(xml_text) }
    let(:spsso_descriptor)  { REXML::XPath.first(xml_doc, "//md:SPSSODescriptor") }
    let(:acs)               { REXML::XPath.first(xml_doc, "//md:AssertionConsumerService") }

    before do
      settings.issuer = "https://example.com"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      settings.assertion_consumer_service_url = "https://foo.example/saml/consume"
    end

    it "generates Pretty Print Service Provider Metadata" do
      xml_text = OneLogin::RubySaml::Metadata.new.generate(settings, true)
      # assert correct xml declaration
      start = "<?xml version='1.0' encoding='UTF-8'?>\n<md:EntityDescriptor"
      assert_equal xml_text[0..start.length-1],start

      assert_equal "https://example.com", REXML::XPath.first(xml_doc, "//md:EntityDescriptor").attribute("entityID").value

      assert_equal "urn:oasis:names:tc:SAML:2.0:protocol", spsso_descriptor.attribute("protocolSupportEnumeration").value
      assert_equal "false", spsso_descriptor.attribute("AuthnRequestsSigned").value
      assert_equal "false", spsso_descriptor.attribute("WantAssertionsSigned").value

      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", REXML::XPath.first(xml_doc, "//md:NameIDFormat").text.strip

      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs.attribute("Binding").value
      assert_equal "https://foo.example/saml/consume", acs.attribute("Location").value      
    end

    it "generates Service Provider Metadata" do
      # assert correct xml declaration
      start = "<?xml version='1.0' encoding='UTF-8'?><md:EntityDescriptor"
      assert_equal xml_text[0..start.length-1], start

      assert_equal "https://example.com", REXML::XPath.first(xml_doc, "//md:EntityDescriptor").attribute("entityID").value

      assert_equal "urn:oasis:names:tc:SAML:2.0:protocol", spsso_descriptor.attribute("protocolSupportEnumeration").value
      assert_equal "false", spsso_descriptor.attribute("AuthnRequestsSigned").value
      assert_equal "false", spsso_descriptor.attribute("WantAssertionsSigned").value

      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", REXML::XPath.first(xml_doc, "//md:NameIDFormat").text.strip

      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs.attribute("Binding").value
      assert_equal "https://foo.example/saml/consume", acs.attribute("Location").value
    end

    describe "when auth requests are signed" do
      let(:cert_node) do
        REXML::XPath.first(
          xml_doc,
          "//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
          "md" => "urn:oasis:names:tc:SAML:2.0:metadata",
          "ds" => "http://www.w3.org/2000/09/xmldsig#"
        )
      end
      let(:cert)  { OpenSSL::X509::Certificate.new(Base64.decode64(cert_node.text)) }

      before do
        settings.security[:authn_requests_signed] = true
        settings.certificate = ruby_saml_cert_text
      end

      it "generates Service Provider Metadata with X509Certificate" do
        assert_equal "true", spsso_descriptor.attribute("AuthnRequestsSigned").value
        assert_equal ruby_saml_cert.to_der, cert.to_der
      end
    end

    describe "when attribute service is configured" do
      let(:attr_svc)  { REXML::XPath.first(xml_doc, "//md:AttributeConsumingService") }
      let(:req_attr)  { REXML::XPath.first(xml_doc, "//md:RequestedAttribute") }

      before do
        settings.attribute_consuming_service.configure do
          service_name "Test Service"
          add_attribute(:name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name", :attribute_value => "Attribute Value")
        end
      end

      it "generates attribute service" do
        assert_equal "true", attr_svc.attribute("isDefault").value
        assert_equal "1", attr_svc.attribute("index").value
        assert_equal REXML::XPath.first(xml_doc, "//md:ServiceName").text.strip, "Test Service"

        assert_equal "Name", req_attr.attribute("Name").value
        assert_equal "Name Format", req_attr.attribute("NameFormat").value
        assert_equal "Friendly Name", req_attr.attribute("FriendlyName").value
        assert_equal "Attribute Value", REXML::XPath.first(xml_doc, "//md:AttributeValue").text.strip
      end
    end

    describe "when the settings indicate to sign (embedded) metadata" do
      before do
        settings.security[:metadata_signed] = true
        settings.certificate = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text
      end

      it "creates a signed metadata" do
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>]m, xml_text
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>], xml_text
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>], xml_text
        signed_metadata = XMLSecurity::SignedDocument.new(xml_text)
        assert signed_metadata.validate_document(ruby_saml_cert_fingerprint, false)        
      end

      describe "when digest and signature methods are specified" do
        before do
          settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
          settings.security[:digest_method] = XMLSecurity::Document::SHA512
        end

        it "creates a signed metadata with specified digest and signature methods" do
          assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>]m, xml_text
          assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'/>], xml_text
          assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha512'/>], xml_text

          signed_metadata_2 = XMLSecurity::SignedDocument.new(xml_text)

          assert signed_metadata_2.validate_document(ruby_saml_cert_fingerprint, false)          
        end
      end
    end
  end
end

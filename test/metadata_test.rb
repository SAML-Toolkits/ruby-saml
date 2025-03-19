# frozen_string_literal: true

require_relative 'test_helper'

class MetadataTest < Minitest::Test

  describe 'Metadata' do
    let(:settings)          { RubySaml::Settings.new }
    let(:xml_text)          { RubySaml::Metadata.new.generate(settings, false) }
    let(:xml_doc)           { Nokogiri::XML(xml_text) }
    let(:spsso_descriptor)  { xml_doc.at_xpath("//md:SPSSODescriptor", "md" => "urn:oasis:names:tc:SAML:2.0:metadata") }
    let(:acs)               { xml_doc.at_xpath("//md:AssertionConsumerService", "md" => "urn:oasis:names:tc:SAML:2.0:metadata") }

    before do
      settings.sp_entity_id = "https://example.com"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      settings.assertion_consumer_service_url = "https://foo.example/saml/consume"
    end

    it "generates Pretty Print Service Provider Metadata" do
      xml_text = RubySaml::Metadata.new.generate(settings, true)
      # assert correct xml declaration
      start = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor"
      assert_equal xml_text[0..start.length-1], start

      assert_equal "https://example.com", xml_doc.at_xpath("//md:EntityDescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})["entityID"]

      assert_equal RubySaml::XML::NS_PROTOCOL, spsso_descriptor["protocolSupportEnumeration"]
      assert_equal "false", spsso_descriptor["AuthnRequestsSigned"]
      assert_equal "false", spsso_descriptor["WantAssertionsSigned"]

      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", xml_doc.at_xpath("//md:NameIDFormat", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}).text.strip

      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs["Binding"]
      assert_equal "https://foo.example/saml/consume", acs["Location"]

      assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
    end

    it "generates Service Provider Metadata" do
      settings.single_logout_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      settings.single_logout_service_url = "https://foo.example/saml/sls"
      xml_metadata = RubySaml::Metadata.new.generate(settings, false)

      start = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor"
      assert_equal xml_metadata[0..start.length-1], start

      doc_metadata = Nokogiri::XML(xml_metadata)
      sls = doc_metadata.at_xpath("//md:SingleLogoutService", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})

      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", sls["Binding"]
      assert_equal "https://foo.example/saml/sls", sls["Location"]
      assert_equal "https://foo.example/saml/sls", sls["ResponseLocation"]
      assert_nil sls["isDefault"]
      assert_nil sls["index"]

      assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
    end

    it "generates Service Provider Metadata with single logout service" do
      start = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor"
      assert_equal xml_text[0..start.length-1], start

      assert_equal "https://example.com", xml_doc.at_xpath("//md:EntityDescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})["entityID"]

      assert_equal RubySaml::XML::NS_PROTOCOL, spsso_descriptor["protocolSupportEnumeration"]
      assert_equal "false", spsso_descriptor["AuthnRequestsSigned"]
      assert_equal "false", spsso_descriptor["WantAssertionsSigned"]

      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", xml_doc.at_xpath("//md:NameIDFormat", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}).text.strip

      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs["Binding"]
      assert_equal "https://foo.example/saml/consume", acs["Location"]

      assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
    end

    it "generates Service Provider Metadata with ValidUntil and CacheDuration" do
      valid_until = Time.now + 172800
      cache_duration = 604800
      xml_metadata = RubySaml::Metadata.new.generate(settings, false, valid_until, cache_duration)
      start = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor"
      assert_equal xml_metadata[0..start.length-1], start

      doc_metadata = Nokogiri::XML(xml_metadata)
      assert_equal valid_until.strftime('%Y-%m-%dT%H:%M:%SZ'), doc_metadata.at_xpath("//md:EntityDescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})["validUntil"]
      assert_equal "PT604800S", doc_metadata.at_xpath("//md:EntityDescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})["cacheDuration"]
    end

    describe "WantAssertionsSigned" do
      it "generates Service Provider Metadata with WantAssertionsSigned = false" do
        settings.security[:want_assertions_signed] = false
        assert_equal "false", spsso_descriptor["WantAssertionsSigned"]
        assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
      end

      it "generates Service Provider Metadata with WantAssertionsSigned = true" do
        settings.security[:want_assertions_signed] = true
        assert_equal "true", spsso_descriptor["WantAssertionsSigned"]
        assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
      end
    end

    describe "with a sign/encrypt certificate" do
      let(:key_descriptors) do
        xml_doc.xpath(
          "//md:KeyDescriptor",
          "md" => "urn:oasis:names:tc:SAML:2.0:metadata"
        )
      end
      let(:cert_nodes) do
        xml_doc.xpath(
          "//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
          "md" => "urn:oasis:names:tc:SAML:2.0:metadata",
          "ds" => "http://www.w3.org/2000/09/xmldsig#"
        )
      end
      let(:cert)  { OpenSSL::X509::Certificate.new(Base64.decode64(cert_nodes[0].text)) }

      before do
        settings.certificate = ruby_saml_cert_text
      end

      it "generates Service Provider Metadata with X509Certificate for sign" do
        assert_equal 1, key_descriptors.length
        assert_equal "signing", key_descriptors[0]["use"]

        assert_equal 1, cert_nodes.length
        assert_equal ruby_saml_cert.to_der, cert.to_der

        assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
      end

      describe "and signed authentication requests" do
        before do
          settings.security[:authn_requests_signed] = true
        end

        it "generates Service Provider Metadata with AuthnRequestsSigned" do
          assert_equal "true", spsso_descriptor["AuthnRequestsSigned"]
          assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
        end
      end

      describe "and encrypted assertions" do
        before do
          settings.security[:want_assertions_encrypted] = true
        end

        it "generates Service Provider Metadata with X509Certificate for encrypt" do
          assert_equal 2, key_descriptors.length

          assert_equal "encryption", key_descriptors[1]["use"]

          assert_equal 2, cert_nodes.length
          assert_equal cert_nodes[0].text, cert_nodes[1].text
          assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
        end
      end
    end

    describe "with a future SP certificate" do
      let(:key_descriptors) do
        xml_doc.xpath(
          "//md:KeyDescriptor",
          "md" => "urn:oasis:names:tc:SAML:2.0:metadata"
        )
      end
      let(:cert_nodes) do
        xml_doc.xpath(
          "//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
          "md" => "urn:oasis:names:tc:SAML:2.0:metadata",
          "ds" => "http://www.w3.org/2000/09/xmldsig#"
        )
      end

      before do
        settings.certificate = ruby_saml_cert_text
        settings.certificate_new = ruby_saml_cert_text2
      end

      it "generates Service Provider Metadata with 2 X509Certificate for sign" do
        assert_equal 2, key_descriptors.length
        assert_equal "signing", key_descriptors[0]["use"]
        assert_equal "signing", key_descriptors[1]["use"]

        cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert_nodes[0].text))
        cert_new = OpenSSL::X509::Certificate.new(Base64.decode64(cert_nodes[1].text))

        assert_equal 2, cert_nodes.length
        assert_equal ruby_saml_cert.to_der, cert.to_der
        assert_equal ruby_saml_cert2.to_der, cert_new.to_der

        assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
      end

      describe "and signed authentication requests" do
        before do
          settings.security[:authn_requests_signed] = true
        end

        it "generates Service Provider Metadata with AuthnRequestsSigned" do
          assert_equal "true", spsso_descriptor["AuthnRequestsSigned"]
          assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
        end
      end

      describe "and encrypted assertions" do
        before do
          settings.security[:want_assertions_encrypted] = true
        end

        it "generates Service Provider Metadata with X509Certificate for encrypt" do
          assert_equal 4, key_descriptors.length
          assert_equal "signing", key_descriptors[0]["use"]
          assert_equal "signing", key_descriptors[1]["use"]
          assert_equal "encryption", key_descriptors[2]["use"]
          assert_equal "encryption", key_descriptors[3]["use"]

          assert_equal 4, cert_nodes.length
          assert_equal cert_nodes[0].text, cert_nodes[2].text
          assert_equal cert_nodes[1].text, cert_nodes[3].text
          assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
        end
      end

      describe "with check_sp_cert_expiration and expired keys" do
        before do
          settings.security[:want_assertions_encrypted] = true
          settings.security[:check_sp_cert_expiration] = true
          valid_pair = CertificateHelper.generate_pem_hash
          early_pair = CertificateHelper.generate_pem_hash(not_before: Time.now + 60)
          expired_pair = CertificateHelper.generate_pem_hash(not_after: Time.now - 60)
          settings.certificate = nil
          settings.certificate_new = nil
          settings.private_key = nil
          settings.sp_cert_multi = {
            signing: [valid_pair, early_pair, expired_pair],
            encryption: [valid_pair, early_pair, expired_pair]
          }
        end

        it "generates Service Provider Metadata with X509Certificate for encrypt" do
          assert_equal 2, key_descriptors.length
          assert_equal "signing", key_descriptors[0]["use"]
          assert_equal "encryption", key_descriptors[1]["use"]

          assert_equal 2, cert_nodes.length
          assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
        end
      end
    end

    describe "when attribute service is configured with multiple attribute values" do
      let(:attr_svc) { xml_doc.at_xpath("//md:AttributeConsumingService", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}) }
      let(:req_attr) { xml_doc.at_xpath("//md:RequestedAttribute", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}) }

      before do
        settings.attribute_consuming_service.configure do
          service_name "Test Service"
          add_attribute(:name => 'Name', :name_format => 'Name Format', :friendly_name => 'Friendly Name', :attribute_value => ['Attribute Value One', false])
        end
      end

      it "generates attribute service" do
        assert_equal "true", attr_svc["isDefault"]
        assert_equal "1", attr_svc["index"]
        assert_equal xml_doc.at_xpath("//md:ServiceName", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}).text.strip, "Test Service"

        assert_equal "Name", req_attr["Name"]
        assert_equal "Name Format", req_attr["NameFormat"]
        assert_equal "Friendly Name", req_attr["FriendlyName"]

        attribute_values = xml_doc.xpath("//saml:AttributeValue", {"saml" => RubySaml::XML::NS_ASSERTION}).map(&:text)
        assert_equal "Attribute Value One", attribute_values[0]
        assert_equal 'false', attribute_values[1]

        assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
      end
    end

    describe "when attribute service is configured" do
      let(:attr_svc) { xml_doc.at_xpath('//md:AttributeConsumingService', {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}) }
      let(:req_attr) { xml_doc.at_xpath('//md:RequestedAttribute', {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}) }

      before do
        settings.attribute_consuming_service.configure do
          service_name "Test Service"
          add_attribute(:name => 'active', :name_format => 'format', :friendly_name => 'Active', :attribute_value => true)
        end
      end

      it "generates attribute service" do
        assert_equal "true", attr_svc["isDefault"]
        assert_equal "1", attr_svc["index"]
        assert_equal xml_doc.at_xpath("//md:ServiceName", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}).text.strip, "Test Service"

        assert_equal 'active', req_attr['Name']
        assert_equal 'format', req_attr['NameFormat']
        assert_equal 'Active', req_attr['FriendlyName']
        assert_equal 'true', xml_doc.at_xpath('//saml:AttributeValue', {"saml" => RubySaml::XML::NS_ASSERTION}).text.strip

        assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
      end

      describe "#service_name" do
        before do
          settings.attribute_consuming_service.service_name("Test2 Service")
        end

        it "change service name" do
          assert_equal xml_doc.at_xpath("//md:ServiceName", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"}).text.strip, "Test2 Service"
        end
      end

      describe "#service_index" do
        before do
          settings.attribute_consuming_service.service_index(2)
        end

        it "change service index" do
          assert_equal "2", attr_svc["index"]
        end
      end
    end

    describe "when the settings indicate to sign (embedded) metadata" do
      before do
        settings.security[:metadata_signed] = true
      end

      it "uses RSA SHA256 by default" do
        @cert, @pkey = CertificateHelper.generate_pair(:rsa)
        settings.certificate, settings.private_key = [@cert, @pkey].map(&:to_pem)
        @fingerprint = OpenSSL::Digest.new('SHA256', @cert.to_der).to_s
        signed_metadata = RubySaml::XML::SignedDocument.new(xml_text)

        assert_match(signature_value_matcher, xml_text)
        assert_match(signature_method_matcher(:rsa, :sha256), xml_text)
        assert_match(digest_method_matcher(:sha256), xml_text)
        assert(signed_metadata.validate_document(@fingerprint, false))
        assert(validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd"))
      end

      each_signature_algorithm do |sp_key_algo, sp_hash_algo|
        describe "specifying algo" do
          before do
            @cert, @pkey = CertificateHelper.generate_pair(sp_key_algo)
            settings.certificate, settings.private_key = [@cert, @pkey].map(&:to_pem)
            @fingerprint = OpenSSL::Digest.new('SHA256', @cert.to_der).to_s
            settings.security[:signature_method] = signature_method(sp_key_algo, sp_hash_algo)
            settings.security[:digest_method] = digest_method(sp_hash_algo)
          end

          it "creates a signed metadata" do
            signed_metadata = RubySaml::XML::SignedDocument.new(xml_text)

            assert_match(signature_value_matcher, xml_text)
            assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), xml_text)
            assert_match(digest_method_matcher(sp_hash_algo), xml_text)

            assert signed_metadata.validate_document(@fingerprint, false)
            assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
          end

          unless sp_hash_algo == :sha256
            it 'using mixed signature and digest methods (signature SHA256)' do
              # RSA is ignored here; only the hash sp_key_algo is used
              settings.security[:signature_method] = RubySaml::XML::RSA_SHA256
              signed_metadata = RubySaml::XML::SignedDocument.new(xml_text)

              assert_match(signature_value_matcher, xml_text)
              assert_match(signature_method_matcher(sp_key_algo, :sha256), xml_text)
              assert_match(digest_method_matcher(sp_hash_algo), xml_text)
              assert(signed_metadata.validate_document(@fingerprint, false))
              assert(validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd"))
            end

            it 'using mixed signature and digest methods (digest SHA256)' do
              settings.security[:digest_method] = RubySaml::XML::SHA256
              signed_metadata = RubySaml::XML::SignedDocument.new(xml_text)

              assert_match(signature_value_matcher, xml_text)
              assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), xml_text)
              assert_match(digest_method_matcher(:sha256), xml_text)
              assert(signed_metadata.validate_document(@fingerprint, false))
              assert(validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd"))
            end
          end

          describe "when custom metadata elements have been inserted" do
            let(:xml_text) { subclass.new.generate(settings, false) }
            let(:subclass) do
              Class.new(RubySaml::Metadata) do
                def add_extras(xml, _settings)
                  xml['md'].IDPSSODescriptor('protocolSupportEnumeration' => RubySaml::XML::NS_PROTOCOL) do
                    xml['md'].NameIDFormat('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
                    xml['md'].SingleSignOnService(
                      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                      'Location' => 'https://foobar.com/sso'
                    )
                  end
                  xml['md'].Organization do
                    xml['md'].OrganizationName('ACME Inc.', 'xml:lang' => 'en-US')
                    xml['md'].OrganizationDisplayName('ACME', 'xml:lang' => 'en-US')
                    xml['md'].OrganizationURL('https://www.acme.com', 'xml:lang' => 'en-US')
                  end
                end
              end
            end

            it "inserts signature as the first child of root element" do
              xml_text = subclass.new.generate(settings, false)
              signed_metadata = RubySaml::XML::SignedDocument.new(xml_text)
              first_child = xml_doc.root.element_children.first

              assert_equal first_child.namespace.prefix, 'ds'
              assert_equal first_child.name, 'Signature'
              assert_match(signature_value_matcher, xml_text)
              assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), xml_text)
              assert_match(digest_method_matcher(sp_hash_algo), xml_text)
              assert signed_metadata.validate_document(@fingerprint, false)
              assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
            end
          end
        end
      end
    end
  end
end

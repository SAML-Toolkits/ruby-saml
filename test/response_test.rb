require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/response'

class RubySamlTest < Minitest::Test

  describe "Response" do
    let(:settings) { OneLogin::RubySaml::Settings.new }
    let(:response) { OneLogin::RubySaml::Response.new(response_document_without_recipient) }
    let(:response_without_attributes) { OneLogin::RubySaml::Response.new(response_document_without_attributes) }
    let(:response_with_signed_assertion) { OneLogin::RubySaml::Response.new(response_document_with_signed_assertion) }
    let(:response_unsigned) { OneLogin::RubySaml::Response.new(response_document_unsigned) }
    let(:response_wrapped) { OneLogin::RubySaml::Response.new(response_document_wrapped) }
    let(:response_multiple_attr_values) { OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values)) }

    it "raise an exception when response is initialized with nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::Response.new(nil) }
    end

    it "be able to parse a document which contains ampersands" do
      XMLSecurity::SignedDocument.any_instance.stubs(:digests_match?).returns(true)
      OneLogin::RubySaml::Response.any_instance.stubs(:validate_conditions).returns(true)

      ampersands_response = OneLogin::RubySaml::Response.new(ampersands_document)
      ampersands_response.settings = settings
      ampersands_response.settings.idp_cert_fingerprint = 'c51985d947f1be57082025050846eb27f6cab783'
      ampersands_response.validate!
    end

    it "adapt namespace" do
      refute_nil response.name_id
      refute_nil response_without_attributes.name_id
      refute_nil response_with_signed_assertion.name_id
    end

    it "default to raw input when a response is not Base64 encoded" do
      decoded  = Base64.decode64(response_document_without_attributes)
      response_from_raw = OneLogin::RubySaml::Response.new(decoded)
      assert response_from_raw.document
    end

    describe "Assertion" do
      it "only retreive an assertion with an ID that matches the signature's reference URI" do
        response_wrapped.stubs(:conditions).returns(nil)
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response_wrapped.settings = settings
        assert_nil response_wrapped.name_id
      end
    end

    describe "#validate!" do
      it "raise when encountering a condition that prevents the document from being valid" do
        assert_raises(OneLogin::RubySaml::ValidationError) do
          response.validate!
        end
      end

      it "raise when No fingerprint or certificate on settings" do
        settings.idp_cert_fingerprint = nil
        settings.idp_cert = nil
        response.settings = settings
        assert_raises(OneLogin::RubySaml::ValidationError, "No fingerprint or certificate on settings") do
          response.validate!
        end
      end

    end

    describe "#validate_structure" do
      it "false when encountering a mailformed element that prevents the document from being valid" do
        response_without_attributes.send(:validate_structure, true)
        assert response_without_attributes.errors.include? "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd"
      end

      it "raise when encountering a mailformed element that prevents the document from being valid" do
        assert_raises(OneLogin::RubySaml::ValidationError) {
          response_without_attributes.send(:validate_structure, false)
        }
      end
    end

    describe "#is_valid?" do
      it "return false when response is initialized with blank data" do
        blank_response = OneLogin::RubySaml::Response.new('')
        assert !blank_response.is_valid?
      end

      it "return false if settings have not been set" do
        assert !response.is_valid?
      end

      it "return true when the response is initialized with valid data" do
        response_unsigned.stubs(:conditions).returns(nil)
        assert !response_unsigned.is_valid?
        response_unsigned.settings = settings
        assert !response_unsigned.is_valid?
        response_unsigned.settings.idp_cert_fingerprint = signature_fingerprint_1
        assert response_unsigned.is_valid?
      end

      it "should be idempotent when the response is initialized with invalid data" do
        response_unsigned.stubs(:conditions).returns(nil)
        response_unsigned.settings = settings
        assert !response_unsigned.is_valid?
        assert !response_unsigned.is_valid?
      end

      it "should be idempotent when the response is initialized with valid data" do
        response_unsigned.stubs(:conditions).returns(nil)
        response_unsigned.settings = settings
        response_unsigned.settings.idp_cert_fingerprint = signature_fingerprint_1
        assert response_unsigned.is_valid?
        assert response_unsigned.is_valid?
      end

      it "return true when using certificate instead of fingerprint" do
        response_unsigned.stubs(:conditions).returns(nil)
        response_unsigned.settings = settings
        response_unsigned.settings.idp_cert = signature_1
        assert response_unsigned.is_valid?
      end

      it "not allow signature wrapping attack" do
        response_unsigned.stubs(:conditions).returns(nil)
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response_unsigned.settings = settings
        assert response_unsigned.is_valid?
        assert_equal response_unsigned.name_id, "test@onelogin.com"
      end

      it "support dynamic namespace resolution on signature elements" do
        no_signature_response = OneLogin::RubySaml::Response.new(fixture("no_signature_ns.xml"))
        no_signature_response.stubs(:conditions).returns(nil)
        no_signature_response.settings = settings
        no_signature_response.settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        XMLSecurity::SignedDocument.any_instance.expects(:validate_signature).returns(true)
        assert no_signature_response.validate!
      end

      it "validate ADFS assertions" do
        adfs_response = OneLogin::RubySaml::Response.new(fixture(:adfs_response_sha256))
        adfs_response.stubs(:conditions).returns(nil)
        settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        adfs_response.settings = settings
        assert adfs_response.validate!
      end

      it "validate the digest" do
        response_with_signed_assertion_2 = OneLogin::RubySaml::Response.new(response_document_with_signed_assertion_2)
        response_with_signed_assertion_2.stubs(:conditions).returns(nil)
        settings.idp_cert = Base64.decode64(certificate_without_head_foot)
        response_with_signed_assertion_2.settings = settings
        assert response_with_signed_assertion_2.validate!
      end

      it "validate SAML 2.0 XML structure" do
        resp_xml = Base64.decode64(response_document_unsigned).gsub(/emailAddress/,'test')
        response_unsigned_mod = OneLogin::RubySaml::Response.new(Base64.encode64(resp_xml))
        response_unsigned_mod.stubs(:conditions).returns(nil)
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response_unsigned_mod.settings = settings
        assert_raises(OneLogin::RubySaml::ValidationError, 'Digest mismatch'){ response_unsigned_mod.validate! }
      end
    end

    describe "#name_id" do
      it "extract the value of the name id element" do
        assert_equal "support@onelogin.com", response.name_id
        assert_equal "someone@example.com", response_with_signed_assertion.name_id
      end

      it "be extractable from an OpenSAML response" do
        response_open_saml = OneLogin::RubySaml::Response.new(fixture(:open_saml))
        assert_equal "someone@example.org", response_open_saml.name_id
      end

      it "be extractable from a Simple SAML PHP response" do
        response_ssp = OneLogin::RubySaml::Response.new(fixture(:simple_saml_php))
        assert_equal "someone@example.com", response_ssp.name_id
      end
    end

    describe "#check_conditions" do
      it "check time conditions" do
        assert !response.send(:validate_conditions, true)
        response_time_updated = OneLogin::RubySaml::Response.new(response_document_without_recipient_with_time_updated)
        assert response_time_updated.send(:validate_conditions, true)
        time = Time.parse("2011-06-14T18:25:01.516Z")
        Time.stubs(:now).returns(time)
        response_with_saml2_namespace = OneLogin::RubySaml::Response.new(response_document_with_saml2_namespace)
        assert response_with_saml2_namespace.send(:validate_conditions, true)
      end

      it "optionally allows for clock drift" do
        # The NotBefore condition in the document is 2011-06-14T18:21:01.516Z
        Timecop.freeze(Time.parse("2011-06-14T18:21:01Z")) do
          special_response_with_saml2_namespace = OneLogin::RubySaml::Response.new(
            response_document_with_saml2_namespace,
            :allowed_clock_drift => 0.515
          )
          assert !special_response_with_saml2_namespace.send(:validate_conditions, true)
        end

        Timecop.freeze(Time.parse("2011-06-14T18:21:01Z")) do
          special_response_with_saml2_namespace = OneLogin::RubySaml::Response.new(
            response_document_with_saml2_namespace,
            :allowed_clock_drift => 0.516
          )
          assert special_response_with_saml2_namespace.send(:validate_conditions, true)
        end
      end
    end

    describe "#attributes" do
      it "extract the first attribute in a hash accessed via its symbol" do
        assert_equal "demo", response.attributes[:uid]
      end

      it "extract the first attribute in a hash accessed via its name" do
        assert_equal "demo", response.attributes["uid"]
      end

      it "extract all attributes" do
        assert_equal "demo", response.attributes[:uid]
        assert_equal "value", response.attributes[:another_value]
      end

      it "work for implicit namespaces" do
        assert_equal "someone@example.com", response_with_signed_assertion.attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
      end

      it "not raise errors about nil/empty attributes for EncryptedAttributes" do
        response_no_cert_and_encrypted_attrs = OneLogin::RubySaml::Response.new(response_document_no_cert_and_encrypted_attrs)
        assert_equal 'Demo', response_no_cert_and_encrypted_attrs.attributes["first_name"]
      end

      it "not raise on responses without attributes" do
        assert_equal OneLogin::RubySaml::Attributes.new, response_unsigned.attributes
      end

      describe "#multiple values" do
        it "extract single value as string" do
          assert_equal "demo", response_multiple_attr_values.attributes[:uid]
        end

        it "extract single value as string in compatibility mode off" do
          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal ["demo"], response_multiple_attr_values.attributes[:uid]
          # classes are not reloaded between tests so restore default
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end

        it "extract first of multiple values as string for b/w compatibility" do
          assert_equal 'value1', response_multiple_attr_values.attributes[:another_value]
        end

        it "extract first of multiple values as string for b/w compatibility in compatibility mode off" do
          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal ['value1', 'value2'], response_multiple_attr_values.attributes[:another_value]
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end

        it "return array with all attributes when asked in XML order" do
          assert_equal ['value1', 'value2'], response_multiple_attr_values.attributes.multi(:another_value)
        end

        it "return array with all attributes when asked in XML order in compatibility mode off" do
          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal ['value1', 'value2'], response_multiple_attr_values.attributes.multi(:another_value)
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end

        it "return first of multiple values when multiple Attribute tags in XML" do
          assert_equal 'role1', response_multiple_attr_values.attributes[:role]
        end

        it "return first of multiple values when multiple Attribute tags in XML in compatibility mode off" do
          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal ['role1', 'role2', 'role3'], response_multiple_attr_values.attributes[:role]
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end

        it "return all of multiple values in reverse order when multiple Attribute tags in XML" do
          assert_equal ['role1', 'role2', 'role3'], response_multiple_attr_values.attributes.multi(:role)
        end

        it "return all of multiple values in reverse order when multiple Attribute tags in XML in compatibility mode off" do
          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal ['role1', 'role2', 'role3'], response_multiple_attr_values.attributes.multi(:role)
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end

        it "return nil value correctly" do
          assert_nil response_multiple_attr_values.attributes[:attribute_with_nil_value]
        end

        it "return nil value correctly when not in compatibility mode off" do
          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal [nil], response_multiple_attr_values.attributes[:attribute_with_nil_value]
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end

        it "return multiple values including nil and empty string" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          assert_equal ["", "valuePresent", nil, nil], response.attributes.multi(:attribute_with_nils_and_empty_strings)
        end

        it "return multiple values from [] when not in compatibility mode off" do
          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal ["", "valuePresent", nil, nil], response_multiple_attr_values.attributes[:attribute_with_nils_and_empty_strings]
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end

        it "check what happens when trying retrieve attribute that does not exists" do
          assert_equal nil, response_multiple_attr_values.attributes[:attribute_not_exists]
          assert_equal nil, response_multiple_attr_values.attributes.single(:attribute_not_exists)
          assert_equal nil, response_multiple_attr_values.attributes.multi(:attribute_not_exists)

          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal nil, response_multiple_attr_values.attributes[:attribute_not_exists]
          assert_equal nil, response_multiple_attr_values.attributes.single(:attribute_not_exists)
          assert_equal nil, response_multiple_attr_values.attributes.multi(:attribute_not_exists)
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end

      end
    end

    describe "#session_expires_at" do
      it "extract the value of the SessionNotOnOrAfter attribute" do
        assert response.session_expires_at.is_a?(Time)

        assert_nil response_without_attributes.session_expires_at
      end
    end

    describe "#issuer" do
      it "return the issuer inside the response assertion" do
        assert_equal "https://app.onelogin.com/saml/metadata/13590", response.issuer
      end

      it "return the issuer inside the response" do
        assert_equal "wibble", response_without_attributes.issuer
      end
    end

    describe "#success" do
      it "find a status code that says success" do
        response.success?
      end
    end

    describe '#xpath_first_from_signed_assertion' do
      it 'not allow arbitrary code execution' do
        malicious_response_document = fixture('response_eval', false)
        malicious_response = OneLogin::RubySaml::Response.new(malicious_response_document)
        malicious_response.send(:xpath_first_from_signed_assertion)
        assert_equal($evalled, nil)
      end
    end

    describe '#sign_document' do
      it 'Sign an unsigned SAML Response XML and initiate the SAML object with it' do
        xml = Base64.decode64(fixture("test_sign.xml"))

        document = XMLSecurity::Document.new(xml)

        formated_cert = OneLogin::RubySaml::Utils.format_cert(ruby_saml_cert_text)
        cert = OpenSSL::X509::Certificate.new(formated_cert)

        formated_private_key = OneLogin::RubySaml::Utils.format_private_key(ruby_saml_key_text)
        private_key = OpenSSL::PKey::RSA.new(formated_private_key)
        document.sign_document(private_key, cert)

        signed_response = OneLogin::RubySaml::Response.new(document.to_s)
        settings.idp_cert = ruby_saml_cert_text
        signed_response.settings = settings
        time = Time.parse("2015-03-18T04:50:24Z")
        Time.stubs(:now).returns(time)
        signed_response.validate!
      end
    end
  end
end

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ResponseTest <  Minitest::Test

  describe "Response" do
    it "raise an exception when response is initialized with nil" do
      err = assert_raises(ArgumentError) do
        OneLogin::RubySaml::Response.new(nil)
      end
      assert_equal "Response cannot be nil", err.message
    end

    it "be able to parse a document which contains ampersands" do
      XMLSecurity::SignedDocument.any_instance.stubs(:digests_match?).returns(true)
      OneLogin::RubySaml::Response.any_instance.stubs(:validate_conditions).returns(true)

      response = OneLogin::RubySaml::Response.new(ampersands_response)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = 'c51985d947f1be57082025050846eb27f6cab783'
      response.settings = settings
      response.validate!
    end

    it "adapt namespace" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert !response.name_id.nil?
      response = OneLogin::RubySaml::Response.new(response_document_2)
      assert !response.name_id.nil?
      response = OneLogin::RubySaml::Response.new(response_document_3)
      assert !response.name_id.nil?
    end

    it "default to raw input when a response is not Base64 encoded" do
      decoded  = Base64.decode64(response_document_2)
      response = OneLogin::RubySaml::Response.new(decoded)
      assert response.document
    end

    describe "Assertion" do
      it "only retreive an assertion with an ID that matches the signature's reference URI" do
        response = OneLogin::RubySaml::Response.new(wrapped_response_2)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response.settings = settings
        assert response.name_id.nil?
      end
    end

    describe "#validate!" do
      it "raise when settings not initialized" do
        response = OneLogin::RubySaml::Response.new(response_document)
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response.validate!
        end
        assert_equal "No settings on response", err.message
      end

      it "raise when encountering a condition that prevents the document from being valid" do
        response = OneLogin::RubySaml::Response.new(response_document)
        response.settings = settings
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response.validate!
        end
        assert_equal "Current time is on or after NotOnOrAfter condition", err.message
      end

      it "raises an exception when no cert or fingerprint provided" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = nil
        settings.idp_cert_fingerprint = nil
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response.validate!
        end
        assert_equal "No fingerprint or certificate on settings", err.message
      end

      it "raise when no signature" do
        response_no_signed_elements = OneLogin::RubySaml::Response.new(read_invalid_response("no_signature.xml.base64"))
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response_no_signed_elements.settings = settings
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response_no_signed_elements.validate!
        end
        assert_equal "Found an unexpected number of Signature Element. SAML Response rejected", err.message
      end

      it "raise when multiple signatures" do
        response_multiple_signed = OneLogin::RubySaml::Response.new(read_invalid_response("multiple_signed.xml.base64"))
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response_multiple_signed.settings = settings
        response_multiple_signed.stubs(:validate_structure).returns(true)
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response_multiple_signed.validate!
        end
        assert_equal "Duplicated ID. SAML Response rejected", err.message
      end

      it "raise when fingerprint missmatch" do
        resp_xml = Base64.decode64(response_document_valid_signed)
        response = OneLogin::RubySaml::Response.new(Base64.encode64(resp_xml))
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response.settings = settings

        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response.validate!
        end
        assert_equal 'Fingerprint mismatch', err.message
      end

    end

    describe "#is_valid?" do
      it "return false when response is initialized with blank data" do
        response = OneLogin::RubySaml::Response.new('')
        assert !response.is_valid?
      end

      it "return false if settings have not been set" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert !response.is_valid?
      end

      it "return false when no cert or fingerprint provided" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = nil
        settings.idp_cert_fingerprint = nil
        assert !response.is_valid?
      end

      it "return true when the response is initialized with valid data" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        response.stubs(:conditions).returns(nil)
        assert !response.is_valid?
        settings = OneLogin::RubySaml::Settings.new
        assert !response.is_valid?
        response.settings = settings
        assert !response.is_valid?
        response.settings.idp_cert_fingerprint = signature_fingerprint_valid_res
        response.validate!
      end

      it "should be idempotent when the response is initialized with invalid data" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        assert !response.is_valid?
        assert !response.is_valid?
      end

      it "should be idempotent when the response is initialized with valid data" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        response.settings.idp_cert_fingerprint = signature_fingerprint_valid_res
        assert response.is_valid?
        assert response.is_valid?
      end

      it "return true when valid response and using fingerprint" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = nil
        settings.idp_cert_fingerprint = "4B:68:C4:53:C7:D9:94:AA:D9:02:5C:99:D5:EF:CF:56:62:87:FE:8D"
        assert response.is_valid?
      end

      it "return true when valid response using certificate" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = valid_cert
        assert response.is_valid?
      end

      it "not allow signature wrapping attack" do
        response = OneLogin::RubySaml::Response.new(response_document_4)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response.settings = settings
        assert !response.is_valid?
        assert response.name_id == "test@onelogin.com"
      end

      it "not allow element wrapping attack" do
        response_wrapped = OneLogin::RubySaml::Response.new(response_document_wrapped)
        response_wrapped.stubs(:conditions).returns(nil)
        response_wrapped.stubs(:validate_subject_confirmation).returns(true)
        settings = OneLogin::RubySaml::Settings.new
        response_wrapped.settings = settings
        response_wrapped.settings.idp_cert_fingerprint = signature_fingerprint_1

        assert !response_wrapped.is_valid?
        assert_nil response_wrapped.name_id
      end

      it "support dynamic namespace resolution on signature elements" do
        response = OneLogin::RubySaml::Response.new(fixture("no_signature_ns.xml"))
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        XMLSecurity::SignedDocument.any_instance.expects(:validate_signature).returns(true)
        assert response.validate!
      end

      it "support signature elements with no KeyInfo if cert provided" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed_without_x509certificate)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = ruby_saml_cert
        settings.idp_cert_fingerprint = nil
        XMLSecurity::SignedDocument.any_instance.expects(:validate_signature).returns(true)
        assert response.validate!
      end

      it "support signature elements with no KeyInfo if cert provided as text" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed_without_x509certificate)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = ruby_saml_cert_text
        settings.idp_cert_fingerprint = nil
        XMLSecurity::SignedDocument.any_instance.expects(:validate_signature).returns(true)
        assert response.validate!
      end

      it "returns an error if the signature contains no KeyInfo, cert is not provided and soft" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed_without_x509certificate)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = nil
        settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        assert !response.is_valid?
      end

      it "raises an exception if the signature contains no KeyInfo, cert is not provided and no soft" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed_without_x509certificate)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = nil
        settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response.validate!
        end
        assert_equal "Certificate element missing in response (ds:X509Certificate) and not cert provided at settings", err.message
      end

      it "validate ADFS assertions" do
        response = OneLogin::RubySaml::Response.new(fixture(:adfs_response_sha256))
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        response.settings = settings
        assert response.validate!
      end

      it "validate the digest" do
        response = OneLogin::RubySaml::Response.new(r1_response_document_6)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert = Base64.decode64(r1_signature_2)
        response.settings = settings
        assert response.validate!
      end

      it "Prevent node text with comment (VU#475445) attack" do
        response_doc = File.read(File.join(File.dirname(__FILE__), "responses", 'response_node_text_attack.xml.base64'))
        response = OneLogin::RubySaml::Response.new(response_doc)

        assert_equal "support@onelogin.com", response.name_id
        assert_equal "smith", response.attributes["surname"]
      end

      describe '#validate_audience' do
        it "return true when sp_entity_id not set or empty" do
          response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
          response.stubs(:conditions).returns(nil)
          settings = OneLogin::RubySaml::Settings.new
          response.settings = settings
          settings.idp_cert_fingerprint = signature_fingerprint_valid_res
          assert response.is_valid?
          settings.sp_entity_id = ''
          assert response.is_valid?
        end

        it "return false when sp_entity_id set to incorrectly" do
          response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
          response.stubs(:conditions).returns(nil)
          settings = OneLogin::RubySaml::Settings.new
          response.settings = settings
          settings.idp_cert_fingerprint = signature_fingerprint_valid_res
          settings.sp_entity_id = 'wrong_audience'
          assert !response.is_valid?
        end

        it "return true when sp_entity_id set to correctly" do
          response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
          response.stubs(:conditions).returns(nil)
          settings = OneLogin::RubySaml::Settings.new
          response.settings = settings
          settings.idp_cert_fingerprint = signature_fingerprint_valid_res
          settings.sp_entity_id = 'https://someone.example.com/audience'
          assert response.is_valid?
        end
      end
    end

    describe "#validate_issuer" do
      it "return true when the issuer of the Message/Assertion matches the IdP entityId" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        response.settings = settings
        assert response.send(:validate_issuer)

        response.settings.idp_entity_id = 'https://app.onelogin.com/saml2'
        assert response.send(:validate_issuer)
      end

      it "return false when the issuer of the Message does not match the IdP entityId" do
        response = OneLogin::RubySaml::Response.new(read_invalid_response("invalid_issuer_message.xml.base64"))
        response.settings = settings
        response.settings.idp_entity_id = 'http://idp.example.com/'
        assert !response.send(:validate_issuer)
      end

      it "return false when the issuer of the Assertion does not match the IdP entityId" do
        response = OneLogin::RubySaml::Response.new(read_invalid_response("invalid_issuer_assertion.xml.base64"))
        response.settings = settings
        response.settings.idp_entity_id = 'http://idp.example.com/'
        assert !response.send(:validate_issuer)
      end
    end

    describe "#name_id" do
      it "extract the value of the name id element" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert_equal "support@onelogin.com", response.name_id

        response = OneLogin::RubySaml::Response.new(response_document_3)
        assert_equal "someone@example.com", response.name_id
      end

      it "be extractable from an OpenSAML response" do
        response = OneLogin::RubySaml::Response.new(fixture(:open_saml))
        assert_equal "someone@example.org", response.name_id
      end

      it "be extractable from a Simple SAML PHP response" do
        response = OneLogin::RubySaml::Response.new(fixture(:simple_saml_php))
        assert_equal "someone@example.com", response.name_id
      end
    end

    describe "#check_conditions" do
      it "check time conditions" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert !response.send(:validate_conditions, true)
        response = OneLogin::RubySaml::Response.new(response_document_6)
        assert response.send(:validate_conditions, true)
        time     = Time.parse("2011-06-14T18:25:01.516Z")
        Time.stubs(:now).returns(time)
        response = OneLogin::RubySaml::Response.new(response_document_5)
        assert response.send(:validate_conditions, true)
      end

      it "optionally allow for clock drift" do
        # The NotBefore condition in the document is 2011-06-14T18:21:01.516Z
        expected_time = Time.parse("2011-06-14T18:21:01Z")
        Time.stubs(:now).returns(expected_time)
        response = OneLogin::RubySaml::Response.new(response_document_5, :allowed_clock_drift => 0.515)
        assert !response.send(:validate_conditions, true)

        expected_time = Time.parse("2011-06-14T18:21:01Z")
        Time.stubs(:now).returns(expected_time)
        response = OneLogin::RubySaml::Response.new(response_document_5, :allowed_clock_drift => 0.516)
        assert response.send(:validate_conditions, true)
      end
    end

    describe "validate_signature" do
      it "raises an exception when no cert or fingerprint provided" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = nil
        settings.idp_cert_fingerprint = nil
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response.send(:validate_signature, false)
        end
        assert_equal "No fingerprint or certificate on settings", err.message
      end

      it "raises an exception when wrong cert provided" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = ruby_saml_cert2
        settings.idp_cert_fingerprint = nil
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response.send(:validate_signature, false)
        end
        assert_equal "Fingerprint mismatch", err.message
      end

      it "raises an exception when wrong fingerprint provided" do
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = nil
        settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response.send(:validate_signature, false)
        end
        assert_equal "Fingerprint mismatch", err.message
      end

      it "raises an exception when no signature" do
        response_no_signed_elements = OneLogin::RubySaml::Response.new(read_invalid_response("no_signature.xml.base64"))
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response_no_signed_elements.settings = settings
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response_no_signed_elements.validate!
        end
        assert_equal "Found an unexpected number of Signature Element. SAML Response rejected", err.message
      end
    end

    describe "#attributes" do
      before do
        @response = OneLogin::RubySaml::Response.new(response_document)
      end

      it "extract the first attribute in a hash accessed via its symbol" do
        assert_equal "demo", @response.attributes[:uid]
      end

      it "extract the first attribute in a hash accessed via its name" do
        assert_equal "demo", @response.attributes["uid"]
      end

      it "extract all attributes" do
        assert_equal "demo", @response.attributes[:uid]
        assert_equal "value", @response.attributes[:another_value]
      end

      it "work for implicit namespaces" do
        response_3 = OneLogin::RubySaml::Response.new(response_document_3)
        assert_equal "someone@example.com", response_3.attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
      end

      it "not raise on responses without attributes" do
        response_4 = OneLogin::RubySaml::Response.new(response_document_4)
        assert_equal OneLogin::RubySaml::Attributes.new, response_4.attributes
      end

      it "extract attributes from all AttributeStatement tags" do
        assert_equal "smith", response_with_multiple_attribute_statements.attributes[:surname]
        assert_equal "bob", response_with_multiple_attribute_statements.attributes[:firstname]
      end

      it "be manipulable by hash methods such as #merge and not raise an exception" do
        @response.attributes.merge({ :testing_attribute => "test" })
      end

      it "be manipulable by hash methods such as #shift and not raise an exception" do
        @response.attributes.shift
      end

      it "be manipulable by hash methods such as #merge! and actually contain the value" do
        @response.attributes.merge!({ :testing_attribute => "test" })
        assert @response.attributes[:testing_attribute]
      end

      it "be manipulable by hash methods such as #shift and actually remove the value" do
        removed_value = @response.attributes.shift
        assert_nil @response.attributes[removed_value[0]]
      end
    end

    describe "#session_expires_at" do
      it "extract the value of the SessionNotOnOrAfter attribute" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert response.session_expires_at.is_a?(Time)

        response = OneLogin::RubySaml::Response.new(response_document_2)
        assert response.session_expires_at.nil?
      end
    end

    describe "#issuer" do
      it "return the issuer inside the response assertion" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert_equal "https://app.onelogin.com/saml/metadata/13590", response.issuer
      end

      it "return the issuer inside the response" do
        response = OneLogin::RubySaml::Response.new(response_document_2)
        assert_equal "wibble", response.issuer
      end
    end

    describe "#success" do
      it "find a status code that says success" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert response.send(:success?)
      end
    end

    describe '#xpath_first_from_signed_assertion' do
      it 'not allow arbitrary code execution' do
        malicious_response_document = fixture('response_eval', false)
        response = OneLogin::RubySaml::Response.new(malicious_response_document)
        response.send(:xpath_first_from_signed_assertion)
        assert_nil $evalled
      end
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

      it "return all of multiple values when multiple Attribute tags in multiple AttributeStatement tags" do
        OneLogin::RubySaml::Attributes.single_value_compatibility = false
        assert_equal ['role1', 'role2', 'role3'], response_with_multiple_attribute_statements.attributes.multi(:role)
        OneLogin::RubySaml::Attributes.single_value_compatibility = true
      end

      it "return nil value correctly" do
        assert_nil response_multiple_attr_values.attributes[:attribute_with_nil_value]
      end

      it "return nil value correctly when not in compatibility mode off" do
        OneLogin::RubySaml::Attributes.single_value_compatibility = false
        assert [nil] == response_multiple_attr_values.attributes[:attribute_with_nil_value]
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
        assert_nil response_multiple_attr_values.attributes[:attribute_not_exists]
        assert_nil response_multiple_attr_values.attributes.single(:attribute_not_exists)
        assert_nil response_multiple_attr_values.attributes.multi(:attribute_not_exists)

        OneLogin::RubySaml::Attributes.single_value_compatibility = false
        assert_nil response_multiple_attr_values.attributes[:attribute_not_exists]
        assert_nil response_multiple_attr_values.attributes.single(:attribute_not_exists)
        assert_nil response_multiple_attr_values.attributes.multi(:attribute_not_exists)
        OneLogin::RubySaml::Attributes.single_value_compatibility = true
      end
    end

    describe "signature wrapping attack with encrypted assertion" do
      it "should not be valid" do
        settings = OneLogin::RubySaml::Settings.new
        settings.private_key = valid_key
        signature_wrapping_attack = read_response("encrypted_new_attack.xml.base64")
        response_wrapped = OneLogin::RubySaml::Response.new(signature_wrapping_attack, :settings => settings)
        response_wrapped.stubs(:conditions).returns(nil)
        response_wrapped.stubs(:validate_subject_confirmation).returns(true)
        settings.idp_cert_fingerprint = "385b1eec71143f00db6af936e2ea12a28771d72c"
        assert !response_wrapped.is_valid?
        err = assert_raises(OneLogin::RubySaml::ValidationError) do
          response_wrapped.validate!
        end
        assert_equal "Found an invalid Signed Element. SAML Response rejected", err.message
      end
    end

    describe "signature wrapping attack - concealed SAML response body" do
      it "should not be valid" do
        settings = OneLogin::RubySaml::Settings.new
        signature_wrapping_attack = read_response("response_with_concealed_signed_assertion.xml")
        response_wrapped = OneLogin::RubySaml::Response.new(signature_wrapping_attack, :settings => settings)
        settings.idp_cert_fingerprint = '4b68c453c7d994aad9025c99d5efcf566287fe8d'
        response_wrapped.stubs(:conditions).returns(nil)
        response_wrapped.stubs(:validate_subject_confirmation).returns(true)
        response_wrapped.stubs(:validate_structure).returns(true)
        assert !response_wrapped.is_valid?
        assert !response_wrapped.validate!
      end
    end

    describe "signature wrapping attack - doubled signed assertion SAML response" do
      it "should not be valid" do
        settings = OneLogin::RubySaml::Settings.new
        signature_wrapping_attack = read_response("response_with_doubled_signed_assertion.xml")
        response_wrapped = OneLogin::RubySaml::Response.new(signature_wrapping_attack, :settings => settings)
        settings.idp_cert_fingerprint = '4b68c453c7d994aad9025c99d5efcf566287fe8d'
        response_wrapped.stubs(:conditions).returns(nil)
        response_wrapped.stubs(:validate_subject_confirmation).returns(true)
        assert !response_wrapped.is_valid?
      end
    end
  end
end

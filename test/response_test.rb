require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class FailingAssertionIdValidator
  def valid?(id)
    false
  end
end

class FailingTimeRangeValidator
  def valid?(begin_time, end_time)
    false
  end
end

class FailingRecipientValidator
  def valid?(recipient_url, assertion_consumer_url)
    false
  end
end

class FailingDestinationValidator
  def valid?(destination_url, assertion_consumer_url)
    false
  end
end

class RubySamlTest < Test::Unit::TestCase

  context "Response" do
    should "raise an exception when response is initialized with nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::Response.new(nil) }
    end

    should "be able to parse a document which contains ampersands" do
      XMLSecurity::SignedDocument.any_instance.stubs(:digests_match?).returns(true)
      OneLogin::RubySaml::Response.any_instance.stubs(:validate_conditions).returns(true)

      response = OneLogin::RubySaml::Response.new(ampersands_response)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = 'c51985d947f1be57082025050846eb27f6cab783'
      response.settings = settings
      response.validate!
    end

    should "adapt namespace" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert !response.name_id.nil?
      response = OneLogin::RubySaml::Response.new(response_document_2)
      assert !response.name_id.nil?
      response = OneLogin::RubySaml::Response.new(response_document_3)
      assert !response.name_id.nil?
    end

    should "default to raw input when a response is not Base64 encoded" do
      decoded  = Base64.decode64(response_document_2)
      response = OneLogin::RubySaml::Response.new(decoded)
      assert response.document
    end

    context "Assertion" do
      should "only retreive an assertion with an ID that matches the signature's reference URI" do
        response = OneLogin::RubySaml::Response.new(wrapped_response_2)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response.settings = settings
        assert response.name_id.nil?
      end
    end

    context "#validate!" do
      should "raise when encountering a condition that prevents the document from being valid" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert_raise(OneLogin::RubySaml::ValidationError) do
          response.validate!
        end
      end
    end

    context "#is_valid?" do
      should "return false when response is initialized with blank data" do
        response = OneLogin::RubySaml::Response.new('')
        assert !response.is_valid?
      end

      should "return false if settings have not been set" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert !response.is_valid?
      end

      should "return true when the response is initialized with valid data" do
        response = OneLogin::RubySaml::Response.new(response_document_4)
        response.stubs(:conditions).returns(nil)
        assert !response.is_valid?
        settings = OneLogin::RubySaml::Settings.new
        assert !response.is_valid?
        response.settings = settings
        assert !response.is_valid?
        settings.idp_cert_fingerprint = signature_fingerprint_1
        assert response.is_valid?
      end

      should "should be idempotent when the response is initialized with invalid data" do
        response = OneLogin::RubySaml::Response.new(response_document_4)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        assert !response.is_valid?
        assert !response.is_valid?
      end

      should "should be idempotent when the response is initialized with valid data" do
        response = OneLogin::RubySaml::Response.new(response_document_4)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert_fingerprint = signature_fingerprint_1
        assert response.is_valid?
        assert response.is_valid?
      end

      should "return true when using certificate instead of fingerprint" do
        response = OneLogin::RubySaml::Response.new(response_document_4)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert = signature_1
        assert response.is_valid?
      end

      should "not allow signature wrapping attack" do
        response = OneLogin::RubySaml::Response.new(response_document_4)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response.settings = settings
        assert response.is_valid?
        assert response.name_id == "test@onelogin.com"
      end

      should "support dynamic namespace resolution on signature elements" do
        response = OneLogin::RubySaml::Response.new(fixture("no_signature_ns.xml"))
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        response.settings = settings
        settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        XMLSecurity::SignedDocument.any_instance.expects(:validate_signature).returns(true)
        assert response.validate!
      end

      should "validate ADFS assertions" do
        response = OneLogin::RubySaml::Response.new(fixture(:adfs_response_sha256))
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
        response.settings = settings
        assert response.validate!
      end

      should "validate the digest" do
        response = OneLogin::RubySaml::Response.new(r1_response_document_6)
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert = Base64.decode64(r1_signature_2)
        response.settings = settings
        assert response.validate!
      end

      should "validate SAML 2.0 XML structure" do
        resp_xml = Base64.decode64(response_document_4).gsub(/emailAddress/,'test')
        response = OneLogin::RubySaml::Response.new(Base64.encode64(resp_xml))
        response.stubs(:conditions).returns(nil)
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response.settings = settings
        assert_raises(OneLogin::RubySaml::ValidationError, 'Digest mismatch'){ response.validate! }
      end

      context "with custom validators" do
        setup do
          @response = OneLogin::RubySaml::Response.new(fixture("no_signature_ns.xml"))
          @response.stubs(:conditions).returns(nil)
          @settings = OneLogin::RubySaml::Settings.new
          @response.settings = @settings
          @settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
          XMLSecurity::SignedDocument.any_instance.stubs(:validate_doc).returns(true)
        end

        should "fail assertion id validation appropriately" do
          @settings.assertion_id_validator = FailingAssertionIdValidator.new
          assert_raises(OneLogin::RubySaml::ValidationError, 'Assertion ID can be use only once') do
            @response.validate!
          end
        end

        should "fail time range validation appropriately" do
          @settings.time_range_validator = FailingTimeRangeValidator.new
          assert_raises(OneLogin::RubySaml::ValidationError, 'Time range validation failed') do
            @response.validate!
          end
        end

        should "fail recipient validation appropriately" do
          @settings.recipient_validator = FailingRecipientValidator.new
          assert_raises(OneLogin::RubySaml::ValidationError, 'Recipient and assertion consumer URL must match') do
            @response.validate!
          end
        end

        should "fail destination validation appropriately" do
          @settings.destination_validator = FailingDestinationValidator.new
          assert_raises(OneLogin::RubySaml::ValidationError, 'Destination and assertion consumer URL must match') do
            @response.validate!
          end
        end
      end
    end

    context "#name_id" do
      should "extract the value of the name id element" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert_equal "support@onelogin.com", response.name_id

        response = OneLogin::RubySaml::Response.new(response_document_3)
        assert_equal "someone@example.com", response.name_id
      end

      should "be extractable from an OpenSAML response" do
        response = OneLogin::RubySaml::Response.new(fixture(:open_saml))
        assert_equal "someone@example.org", response.name_id
      end

      should "be extractable from a Simple SAML PHP response" do
        response = OneLogin::RubySaml::Response.new(fixture(:simple_saml_php))
        assert_equal "someone@example.com", response.name_id
      end
    end

    context "#check_conditions" do
      should "check time conditions" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert !response.send(:validate_conditions, true)
        response = OneLogin::RubySaml::Response.new(response_document_6)
        assert response.send(:validate_conditions, true)
        time     = Time.parse("2011-06-14T18:25:01.516Z")
        Time.stubs(:now).returns(time)
        response = OneLogin::RubySaml::Response.new(response_document_5)
        assert response.send(:validate_conditions, true)
      end

      should "optionally allow for clock drift" do
        # The NotBefore condition in the document is 2011-06-14T18:21:01.516Z
        Time.stubs(:now).returns(Time.parse("2011-06-14T18:21:01Z"))
        response = OneLogin::RubySaml::Response.new(response_document_5, :allowed_clock_drift => 0.515)
        assert !response.send(:validate_conditions, true)

        Time.stubs(:now).returns(Time.parse("2011-06-14T18:21:01Z"))
        response = OneLogin::RubySaml::Response.new(response_document_5, :allowed_clock_drift => 0.516)
        assert response.send(:validate_conditions, true)
      end
    end

    context "#attributes" do
      should "extract the first attribute in a hash accessed via its symbol" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert_equal "demo", response.attributes[:uid]
      end

      should "extract the first attribute in a hash accessed via its name" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert_equal "demo", response.attributes["uid"]
      end

      should "extract all attributes" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert_equal "demo", response.attributes[:uid]
        assert_equal "value", response.attributes[:another_value]
      end

      should "work for implicit namespaces" do
        response = OneLogin::RubySaml::Response.new(response_document_3)
        assert_equal "someone@example.com", response.attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
      end

      should "not raise errors about nil/empty attributes for EncryptedAttributes" do
        response = OneLogin::RubySaml::Response.new(response_document_7)
        assert_equal 'Demo', response.attributes["first_name"]
      end

      should "not raise on responses without attributes" do
        response = OneLogin::RubySaml::Response.new(response_document_4)
        assert_equal OneLogin::RubySaml::Attributes.new, response.attributes
      end

      context "#multiple values" do
        should "extract single value as string" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          assert_equal "demo", response.attributes[:uid]
        end

        should "extract first of multiple values as string for b/w compatibility" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          assert_equal 'value1', response.attributes[:another_value]
        end

        should "return array with all attributes when asked in XML order" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          assert_equal ['value1', 'value2'], response.attributes.multi(:another_value)
        end

        should "return first of multiple values when multiple Attribute tags in XML" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          assert_equal 'role1', response.attributes[:role]
        end

        should "return all of multiple values in reverse order when multiple Attribute tags in XML" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          assert_equal ['role1', 'role2', 'role3'], response.attributes.multi(:role)
        end

        should "return nil value correctly" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          assert_nil response.attributes[:attribute_with_nil_value]
        end

        should "return multiple values including nil and empty string" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          assert_equal ["", "valuePresent", nil, nil], response.attributes.multi(:attribute_with_nils_and_empty_strings)
        end

        should "return multiple values from [] when not in compatibility mode" do
          response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
          OneLogin::RubySaml::Attributes.single_value_compatibility = false
          assert_equal ["", "valuePresent", nil, nil], response.attributes[:attribute_with_nils_and_empty_strings]
          # classes are not reloaded between tests so restore default
          OneLogin::RubySaml::Attributes.single_value_compatibility = true
        end
      end
    end

    context "#session_expires_at" do
      should "extract the value of the SessionNotOnOrAfter attribute" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert response.session_expires_at.is_a?(Time)

        response = OneLogin::RubySaml::Response.new(response_document_2)
        assert response.session_expires_at.nil?
      end
    end

    context "#issuer" do
      should "return the issuer inside the response assertion" do
        response = OneLogin::RubySaml::Response.new(response_document)
        assert_equal "https://app.onelogin.com/saml/metadata/13590", response.issuer
      end

      should "return the issuer inside the response" do
        response = OneLogin::RubySaml::Response.new(response_document_2)
        assert_equal "wibble", response.issuer
      end
    end

    context "#success" do
      should "find a status code that says success" do
        response = OneLogin::RubySaml::Response.new(response_document)
        response.success?
      end
    end

  end
end

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RubySamlTest < Test::Unit::TestCase

  context "Response" do
    should "raise an exception when response is initialized with nil" do
      assert_raises(ArgumentError) { Onelogin::Saml::Response.new(nil) }
    end

    should "adapt namespace" do
      response = Onelogin::Saml::Response.new(response_document)
      assert !response.name_id.nil?
      response = Onelogin::Saml::Response.new(response_document_2)
      assert !response.name_id.nil?
      response = Onelogin::Saml::Response.new(response_document_3)
      assert !response.name_id.nil?
    end

    context "#validate!" do
      should "raise when encountering a condition that prevents the document from being valid" do
        response = Onelogin::Saml::Response.new(response_document)
        assert_raise(Onelogin::Saml::ValidationError) do
          response.validate!
        end
      end
    end

    context "#is_valid?" do
      should "return false when response is initialized with blank data" do
        response = Onelogin::Saml::Response.new('')
        assert !response.is_valid?
      end

      should "return false if settings have not been set" do
        response = Onelogin::Saml::Response.new(response_document)
        assert !response.is_valid?
      end

      should "return true when the response is initialized with valid data" do
        response = Onelogin::Saml::Response.new(response_document_4)
        response.stubs(:conditions).returns(nil)
        assert !response.is_valid?
        settings = Onelogin::Saml::Settings.new
        assert !response.is_valid?
        response.settings = settings
        assert !response.is_valid?
        settings.idp_cert_fingerprint = signature_fingerprint_1
        assert response.is_valid?
      end

      should "not allow signature wrapping attack" do
        response = Onelogin::Saml::Response.new(response_document_4)
        response.stubs(:conditions).returns(nil)
        settings = Onelogin::Saml::Settings.new
        settings.idp_cert_fingerprint = signature_fingerprint_1
        response.settings = settings
        assert response.is_valid?
        assert response.name_id == "test@onelogin.com"
      end

    end

    context "#name_id" do
      should "extract the value of the name id element" do
        response = Onelogin::Saml::Response.new(response_document)
        assert_equal "support@onelogin.com", response.name_id

        response = Onelogin::Saml::Response.new(response_document_3)
        assert_equal "someone@example.com", response.name_id
      end

      should_eventually "be extractable from OpenSAML" do
        response = Onelogin::Saml::Response.new(fixture(:open_saml))
        assert_equal "someone@example.org", response.name_id
      end
    end

    context "#check_conditions" do
      should "check time conditions" do
        response = Onelogin::Saml::Response.new(response_document)
        assert !response.send(:validate_conditions, true)
        response = Onelogin::Saml::Response.new(response_document_6)
        assert response.send(:validate_conditions, true)
        time     = Time.parse("2011-06-14T18:25:01.516Z")
        Time.stubs(:now).returns(time)
        response = Onelogin::Saml::Response.new(response_document_5)
        assert response.send(:validate_conditions, true)
      end
    end

    context "#attributes" do
      should "extract the first attribute in a hash accessed via its symbol" do
        response = Onelogin::Saml::Response.new(response_document)
        assert_equal "demo", response.attributes[:uid]
      end

      should "extract the first attribute in a hash accessed via its name" do
        response = Onelogin::Saml::Response.new(response_document)
        assert_equal "demo", response.attributes["uid"]
      end

      should "extract all attributes" do
        response = Onelogin::Saml::Response.new(response_document)
        assert_equal "demo", response.attributes[:uid]
        assert_equal "value", response.attributes[:another_value]
      end

      should "work for implicit namespaces" do
        response = Onelogin::Saml::Response.new(response_document_3)
        assert_equal "someone@example.com", response.attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
      end

      should "not raise on responses without attributes" do
        response = Onelogin::Saml::Response.new(response_document_4)
        assert_equal Hash.new, response.attributes
      end
    end

    context "#session_expires_at" do
      should "extract the value of the SessionNotOnOrAfter attribute" do
        response = Onelogin::Saml::Response.new(response_document)
        assert response.session_expires_at.is_a?(Time)

        response = Onelogin::Saml::Response.new(response_document_2)
        assert response.session_expires_at.nil?
      end
    end

  end

end

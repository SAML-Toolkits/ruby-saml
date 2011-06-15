require 'test_helper'

class RubySamlTest < Test::Unit::TestCase

  context "Settings" do
    setup do
      @settings = Onelogin::Saml::Settings.new
    end
    should "should provide getters and settings" do
      accessors = [
        :assertion_consumer_service_url, :issuer, :sp_name_qualifier, :sp_name_qualifier,
        :idp_sso_target_url, :idp_cert_fingerprint, :name_identifier_format
      ]

      accessors.each do |accessor|
        value = Kernel.rand
        @settings.send("#{accessor}=".to_sym, value)
        assert_equal value, @settings.send(accessor)
      end
    end
  end

  context "Response" do
    should "provide setter for a logger" do
      response = Onelogin::Saml::Response.new('')
      assert response.logger = 'hello'
    end

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
        response.expects(:check_conditions).returns(true)
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
        response.expects(:check_conditions).returns(true)
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
    end

    context "#check_conditions" do
      should "check time conditions" do
        response = Onelogin::Saml::Response.new(response_document)
        assert !response.check_conditions
        response = Onelogin::Saml::Response.new(response_document_6)
        assert response.check_conditions
        time     = Time.parse("2011-06-14T18:25:01.516Z")
        Time.stubs(:now).returns(time)
        response = Onelogin::Saml::Response.new(response_document_5)
        assert response.check_conditions
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

  context "Authrequest" do
    should "create the SAMLRequest URL parameter" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://stuff.com"
      auth_url = Onelogin::Saml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/stuff\.com\?SAMLRequest=/
      payload = CGI.unescape(auth_url.split("=").last)
    end

    should "accept extra parameters" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://stuff.com"

      auth_url = Onelogin::Saml::Authrequest.new.create(settings, { :hello => "there" })
      assert auth_url =~ /&hello=there$/

      auth_url = Onelogin::Saml::Authrequest.new.create(settings, { :hello => nil })
      assert auth_url =~ /&hello=$/
    end
  end
end

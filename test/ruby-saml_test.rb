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
        response = Onelogin::Saml::Response.new(response_document)
        settings = Onelogin::Saml::Settings.new
        settings.idp_cert_fingerprint = 'hello'
        response.settings = settings
        assert !response.is_valid?
        document = stub()
        document.stubs(:validate).returns(true)
        response.document = document
        assert response.is_valid?
      end
    end

    context "#name_id" do
      should "extract the value of the name id element" do
        response = Onelogin::Saml::Response.new(response_document)
        assert_equal "support@onelogin.com", response.name_id
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
    end

    context "#session_expires_at" do
      should "extract the value of the SessionNotOnOrAfter attribute" do
        response = Onelogin::Saml::Response.new(response_document)
        assert response.session_expires_at.is_a?(Time)
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

  context "EntityDescription" do
    should "generate a correct entity descriptor" do
      descriptor = Onelogin::Saml::EntityDescription.new
      xml = descriptor.generate({
        "entity_id" => "http://test.no/",
        "name_id_format" => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        "assertion_consumer_service_location" => "http://localhost:3000/saml/consume"
      })

      assert_equal xml, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>

<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"http://test.no/\">
 <SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">
   <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
   <AssertionConsumerService
    isDefault=\"true\"
    index=\"0\"
    Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
    Location=\"http://localhost:3000/saml/consume\"/>
 </SPSSODescriptor>
 <RoleDescriptor xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:query=\"urn:oasis:names:tc:SAML:metadata:ext:query\" xsi:type=\"query:AttributeQueryDescriptorType\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>
 <XACMLAuthzDecisionQueryDescriptor WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>
</EntityDescriptor>"
    end
  end
end

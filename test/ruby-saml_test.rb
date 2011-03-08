#encoding: utf-8
require 'test_helper'

class RubySamlTest < Test::Unit::TestCase
  include Onelogin::Saml::Codeing


  context "Settings" do
    setup do
      @settings = Onelogin::Saml::Settings.new
    end
    should "should provide getters and settings" do
      accessors = [
        :assertion_consumer_service_url, :issuer, :sp_name_qualifier,
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

    context "#sessionindex" do
      should "get the sessionindex" do
        response = Onelogin::Saml::Response.new(response_document)
        assert_equal "_531c32d283bdff7e04e487bcdbc4dd8d", response.sessionindex
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

  context "Logoutrequest" do

    setup do
      UUID.expects(:new).returns(stub(:generate => "da64beb0-2ac4-012e-a9c9-48bcc8e9f44d"))
      @settings = Onelogin::Saml::Settings.new
      @settings.issuer = "issuer"
      @settings.sp_name_qualifier ="sp name"
      @settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      @settings.idp_slo_target_url ="http://slotarget.com/"

      Onelogin::Saml::Logoutrequest.stubs(:timestamp).returns("timestamb")
    end

    should "generate a correct logout request" do
      logoutrequest = Onelogin::Saml::Logoutrequest.new

      @settings.name_id = "demo"
      @settings.sessionindex = "s2c8e391dbfcb2f71796595c803cf8b4079119ff01"
      logout_xml = logoutrequest.xml(@settings, "test")

      expected_xml = <<-EOF
    <samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
            ID=\"da64beb0-2ac4-012e-a9c9-48bcc8e9f44d\" Version=\"2.0\" IssueInstant=\"test\">
                <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">issuer</saml:Issuer>
                <saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
                    NameQualifier=\"sp name\"
                    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">demo</saml:NameID>
            <samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">s2c8e391dbfcb2f71796595c803cf8b4079119ff01</samlp:SessionIndex>
        </samlp:LogoutRequest>
      EOF

      assert_equal expected_xml.strip, logout_xml.strip
    end


    should "generate a correct request" do
      logoutrequest = Onelogin::Saml::Logoutrequest.new
      @settings.name_id = "demo"
      @settings.sessionindex = "sessionindex"
      logout_url = logoutrequest.create(@settings, {})

      expected_url = "http://slotarget.com/?SAMLRequest=nZJNa8MwDEDv%2FRXG92xZCKMxTWBQBoFusBV2VxxlGGI7sxToz18%2Bui1hWw%2FV%0A0ZbekywLMceOwLadOvh33%2FMrfvRILE62daSmm1z2wSkPZEg5sEiKtTo%2BPB1U%0AchOrLnj22rdyIxZR7nNZw31aYRVHCeg0iu8SjCDTWZRuK623mDVpWkvxhoGM%0Ad7kcYFKURD2Wjhgc55LNYGOwlSxW9O%2Bu1ZQfFt1ebhaIMPCgk4WZKne3C8x%2F%0AkueBU%2B6vkPzijTHSXnpoTWMw5JI6MSL%2Bzn30wQJf1o0npo6aKVVxAEcGHcui%0ARuvP880TrOc7r%2F2INL5%2F6Wo8XbH1guZ6M9bPtjXzR%2Fp1u%2FpoxeYT%0A"
      assert_equal expected_url, logout_url
    end

  end

  context "Logoutresponse" do
    should "validate the response" do
      
      issuer = "https://test-idp.test.no:443/issuer"
      transaction_id = "adflkjalkfjalsdfjlaskjdf"
      params = {}
      logout_xml = "<samlp:LogoutResponse  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
                          ID=\"sedf164edc2121a23d4ca4b31d35261e5563dc352\" Version=\"2.0\" 
                          IssueInstant=\"2011-03-07T14:43:34Z\" Destination=\"http://localhost:3000/saml/consume_logout\" 
                          InResponseTo=\"#{transaction_id}\">
                          <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{issuer}</saml:Issuer>
                          <samlp:Status xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">
                          <samlp:StatusCode  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
                          Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\">
                          </samlp:StatusCode>
                          </samlp:Status>
                          </samlp:LogoutResponse>"


      params["SAMLResponse"] = encode(deflate(logout_xml))
      logoutresponse = Onelogin::Saml::Logoutresponse.new(params["SAMLResponse"])

      assert_equal logoutresponse.issuer, issuer
      assert_equal logoutresponse.in_response_to, transaction_id
      assert_equal true, logoutresponse.success?
    end

    should "validate the a failing response" do

      
      logout_xml = "<samlp:LogoutResponse  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
                          ID=\"sedf164edc2121a23d4ca4b31d35261e5563dc352\" Version=\"2.0\"
                          IssueInstant=\"2011-03-07T14:43:34Z\" Destination=\"http://localhost:3000/saml/consume_logout\"
                          InResponseTo=\"adflkjalkfjalsdfjlaskjdf\">
                          <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://test-idp.test.no:443/issuer</saml:Issuer>
                          <samlp:Status xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">
                          <samlp:StatusCode  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
                          Value=\"urn:oasis:names:tc:SAML:2.0:status:Requester\">
                          </samlp:StatusCode>
                          </samlp:Status>
                          </samlp:LogoutResponse>"


      logoutresponse = Onelogin::Saml::Logoutresponse.new(encode(deflate(logout_xml)))

      assert_equal false, logoutresponse.success?
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

      expected_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>

<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"http://test.no/\">
 <SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">

   <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
   <AssertionConsumerService
    isDefault=\"true\"
    index=\"0\"
    Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
    Location=\"http://localhost:3000/saml/consume\"/>
 </SPSSODescriptor>
 <RoleDescriptor xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:query=\"urn:oasis:names:tc:SAML:metadata:ext:query\" xsi:type=\"query:AttributeQueryDescriptorType\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>\n <XACMLAuthzDecisionQueryDescriptor WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>
</EntityDescriptor>"

      assert_equal expected_xml.gsub(" ", ""), xml.gsub(" ", "")
    end

    context "with slo" do
      should "generate correct xml part" do
        descriptor = Onelogin::Saml::EntityDescription.new
      xml = descriptor.generate({
        "entity_id" => "http://test.no/",
        "name_id_format" => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        "assertion_consumer_service_location" => "http://localhost:3000/saml/consume",

        "single_logout_service_location" => "slo_location",
        "single_logout_service_response_location" => "response_location"
      })

      expected_xml = "     <SingleLogoutService
      Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"
      Location=\"slo_location\"
      ResponseLocation=\"response_location\"/>"

        assert xml.include?(expected_xml), "Xml does not include\nfull:#{xml}\n\nincluded: #{expected_xml}"
      end
    end
  end



  
end

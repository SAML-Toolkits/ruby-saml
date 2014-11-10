require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RequestTest < Test::Unit::TestCase

  context "Authrequest" do
    should "create the deflated SAMLRequest URL parameter" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/example\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match /^<samlp:AuthnRequest/, inflated
    end

    should "create the deflated SAMLRequest URL parameter including the Destination" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match /<samlp:AuthnRequest[^<]* Destination='http:\/\/example.com'/, inflated
    end

    should "create the SAMLRequest URL parameter without deflating" do
      settings = OneLogin::RubySaml::Settings.new
      settings.compress_request = false
      settings.idp_sso_target_url = "http://example.com"
      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/example\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      assert_match /^<samlp:AuthnRequest/, decoded
    end

    should "create the SAMLRequest URL parameter with IsPassive" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.passive = true
      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/example\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match /<samlp:AuthnRequest[^<]* IsPassive='true'/, inflated
    end

    should "create the SAMLRequest URL parameter with ProtocolBinding" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.protocol_binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/example\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match /<samlp:AuthnRequest[^<]* ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'/, inflated
    end

    should "create the SAMLRequest URL parameter with AttributeConsumingServiceIndex" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.attributes_index = 30
      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/example\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close
      assert_match /<samlp:AuthnRequest[^<]* AttributeConsumingServiceIndex='30'/, inflated
    end

    should "create the SAMLRequest URL parameter with ForceAuthn" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.force_authn = true
      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/example\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close
      assert_match /<samlp:AuthnRequest[^<]* ForceAuthn='true'/, inflated
    end

    should "accept extra parameters" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"

      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings, { :hello => "there" })
      assert auth_url =~ /&hello=there$/

      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings, { :hello => nil })
      assert auth_url =~ /&hello=$/
    end

    context "when the target url doesn't contain a query string" do
      should "create the SAMLRequest parameter correctly" do
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_sso_target_url = "http://example.com"

        auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
        assert auth_url =~ /^http:\/\/example.com\?SAMLRequest/
      end
    end

    context "when the target url contains a query string" do
      should "create the SAMLRequest parameter correctly" do
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_sso_target_url = "http://example.com?field=value"

        auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
        assert auth_url =~ /^http:\/\/example.com\?field=value&SAMLRequest/
      end
    end

    should "create the saml:AuthnContextClassRef element correctly" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.authn_context = 'secure/name/password/uri'
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef[\S ]+>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    should "create the saml:AuthnContextClassRef with comparison exact" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.authn_context = 'secure/name/password/uri'
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<samlp:RequestedAuthnContext[\S ]+Comparison='exact'/
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef[\S ]+>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    should "create the saml:AuthnContextClassRef with comparison minimun" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.authn_context = 'secure/name/password/uri'
      settings.authn_context_comparison = 'minimun'
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<samlp:RequestedAuthnContext[\S ]+Comparison='minimun'/
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef[\S ]+>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    should "create the saml:AuthnContextDeclRef element correctly" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.authn_context_decl_ref = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<saml:AuthnContextDeclRef[\S ]+>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport<\/saml:AuthnContextDeclRef>/
    end

    should 'create the samlp:Extensions element correctly' do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = 'http://example.com'
      settings.authn_request_extensions_builder = ->(extension_context) {
        extension = extension_context.add_element 'MyExtension', {
          "xmlns" => 'http://example.com/idp-extensions'
        }
        extension.text = "SomeValue"
      }
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<samlp:Extensions[\S ]+>[\S ]+<\/samlp:Extensions>/
      assert auth_doc.to_s =~ /<MyExtension[\S ]+http:\/\/example.com\/idp-extensions[\S ]+>[\S ]+<\/MyExtension>/
    end
  end
end

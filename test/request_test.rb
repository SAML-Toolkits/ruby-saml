require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/authrequest'

class RequestTest < Minitest::Test

  describe "Authrequest" do
    it "create the deflated SAMLRequest URL parameter" do
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

    it "create the deflated SAMLRequest URL parameter including the Destination" do
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

    it "create the SAMLRequest URL parameter without deflating" do
      settings = OneLogin::RubySaml::Settings.new
      settings.compress_request = false
      settings.idp_sso_target_url = "http://example.com"
      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/example\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      assert_match /^<samlp:AuthnRequest/, decoded
    end

    it "create the SAMLRequest URL parameter with IsPassive" do
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

    it "create the SAMLRequest URL parameter with ProtocolBinding" do
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

    it "create the SAMLRequest URL parameter with AttributeConsumingServiceIndex" do
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

    it "create the SAMLRequest URL parameter with ForceAuthn" do
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

    it "accept extra parameters" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"

      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings, { :hello => "there" })
      assert auth_url =~ /&hello=there$/

      auth_url = OneLogin::RubySaml::Authrequest.new.create(settings, { :hello => nil })
      assert auth_url =~ /&hello=$/
    end

    describe "when the target url doesn't contain a query string" do
      it "create the SAMLRequest parameter correctly" do
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_sso_target_url = "http://example.com"

        auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
        assert auth_url =~ /^http:\/\/example.com\?SAMLRequest/
      end
    end

    describe "when the target url contains a query string" do
      it "create the SAMLRequest parameter correctly" do
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_sso_target_url = "http://example.com?field=value"

        auth_url = OneLogin::RubySaml::Authrequest.new.create(settings)
        assert auth_url =~ /^http:\/\/example.com\?field=value&SAMLRequest/
      end
    end

    describe "when the settings indicate to sign (embedded) the request" do
      it "create a signed request" do
        settings = OneLogin::RubySaml::Settings.new
        settings.compress_request = false
        settings.idp_sso_target_url = "http://example.com?field=value"
        settings.security[:authn_requests_signed] = true
        settings.security[:embed_sign] = true
        settings.certificate  = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text

        params = OneLogin::RubySaml::Authrequest.new.create_params(settings)
        request_xml = Base64.decode64(params["SAMLRequest"])
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], request_xml
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>], request_xml
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>], request_xml
      end

      it "create a signed request with 256 digest and signature methods" do
        settings = OneLogin::RubySaml::Settings.new
        settings.compress_request = false
        settings.idp_sso_target_url = "http://example.com?field=value"
        settings.security[:authn_requests_signed] = true
        settings.security[:embed_sign] = true
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        settings.security[:digest_method] = XMLSecurity::Document::SHA512
        settings.certificate  = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text

        params = OneLogin::RubySaml::Authrequest.new.create_params(settings)
        request_xml = Base64.decode64(params["SAMLRequest"])
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], request_xml
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'/>], request_xml
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha512'/>], request_xml
      end
    end

    describe "when the settings indicate to sign the request" do
      it "create a signature parameter" do
        settings = OneLogin::RubySaml::Settings.new
        settings.compress_request = false
        settings.idp_sso_target_url = "http://example.com?field=value"
        settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
        settings.security[:authn_requests_signed] = true
        settings.security[:embed_sign] = false
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        settings.certificate  = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text

        params = OneLogin::RubySaml::Authrequest.new.create_params(settings)
        assert params['Signature']
        assert params['SigAlg'] == XMLSecurity::Document::RSA_SHA1

        # signature_method only affects the embedeed signature
        settings.security[:signature_method] = XMLSecurity::Document::SHA256
        params = OneLogin::RubySaml::Authrequest.new.create_params(settings)
        assert params['Signature']
        assert params['SigAlg'] == XMLSecurity::Document::RSA_SHA1
      end
    end

    it "create the saml:AuthnContextClassRef element correctly" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.authn_context = 'secure/name/password/uri'
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    it "create the saml:AuthnContextClassRef with comparison exact" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.authn_context = 'secure/name/password/uri'
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<samlp:RequestedAuthnContext[\S ]+Comparison='exact'/
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    it "create the saml:AuthnContextClassRef with comparison minimun" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.authn_context = 'secure/name/password/uri'
      settings.authn_context_comparison = 'minimun'
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<samlp:RequestedAuthnContext[\S ]+Comparison='minimun'/
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    it "create the saml:AuthnContextDeclRef element correctly" do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      settings.authn_context_decl_ref = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      auth_doc = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<saml:AuthnContextDeclRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport<\/saml:AuthnContextDeclRef>/
    end
  end
end

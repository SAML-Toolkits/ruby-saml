require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RequestTest < Test::Unit::TestCase

  context "Authrequest" do
    should "create the deflated SAMLRequest URL parameter" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      auth_url = Onelogin::Saml::Authrequest.new.create(settings)
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
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://example.com"
      auth_url = Onelogin::Saml::Authrequest.new.create(settings)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match /<samlp:AuthnRequest[^<]* Destination='http:\/\/example.com'/, inflated
    end

    should "create the SAMLRequest URL parameter without deflating" do
      settings = Onelogin::Saml::Settings.new
      settings.compress_request = false
      settings.idp_sso_target_url = "http://example.com"
      auth_url = Onelogin::Saml::Authrequest.new.create(settings)
      assert auth_url =~ /^http:\/\/example\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      assert_match /^<samlp:AuthnRequest/, decoded
    end

    should "accept extra parameters" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://example.com"

      auth_url = Onelogin::Saml::Authrequest.new.create(settings, { :hello => "there" })
      assert auth_url =~ /&hello=there$/

      auth_url = Onelogin::Saml::Authrequest.new.create(settings, { :hello => nil })
      assert auth_url =~ /&hello=$/
    end

    context "when the target url doesn't contain a query string" do
      should "create the SAMLRequest parameter correctly" do
        settings = Onelogin::Saml::Settings.new
        settings.idp_sso_target_url = "http://example.com"
  
        auth_url = Onelogin::Saml::Authrequest.new.create(settings)
        assert auth_url =~ /^http:\/\/example.com\?SAMLRequest/
      end
    end

    context "when the target url contains a query string" do
      should "create the SAMLRequest parameter correctly" do
        settings = Onelogin::Saml::Settings.new
        settings.idp_sso_target_url = "http://example.com?field=value"
  
        auth_url = Onelogin::Saml::Authrequest.new.create(settings)
        assert auth_url =~ /^http:\/\/example.com\?field=value&SAMLRequest/
      end
    end
  end
end

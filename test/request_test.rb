require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RequestTest < Test::Unit::TestCase

  context "Authrequest" do
    should "create the deflated SAMLRequest URL parameter" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://stuff.com"
      action, auth_url = Onelogin::Saml::Authrequest.new(settings).create
		assert_match "GET", action
		
      assert auth_url =~ /^http:\/\/stuff\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match /^<samlp:AuthnRequest/, inflated
    end

    should "accept extra parameters" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://stuff.com"

      action, auth_url = Onelogin::Saml::Authrequest.new(settings).create({ :hello => "there" })
      assert auth_url =~ /&hello=there$/

      action, auth_url = Onelogin::Saml::Authrequest.new(settings).create({ :hello => nil })
      assert auth_url =~ /&hello=$/
    end
  end
end

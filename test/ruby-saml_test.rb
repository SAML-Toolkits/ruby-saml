require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

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

  context "Authrequest" do
    should "create the deflated SAMLRequest URL parameter" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://stuff.com"
      auth_url = Onelogin::Saml::Authrequest.new.create(settings)
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

      auth_url = Onelogin::Saml::Authrequest.new.create(settings, { :hello => "there" })
      assert auth_url =~ /&hello=there$/

      auth_url = Onelogin::Saml::Authrequest.new.create(settings, { :hello => nil })
      assert auth_url =~ /&hello=$/
    end
  end
end

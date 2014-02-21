require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RequestTest < Test::Unit::TestCase

  context "Logoutrequest" do
    settings = Onelogin::Saml::Settings.new

    should "create the deflated SAMLRequest URL parameter" do
      settings.idp_slo_target_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"

      unauth_url = Onelogin::Saml::Logoutrequest.new.create(settings)
      assert unauth_url =~ /^http:\/\/unauth\.com\/logout\?SAMLRequest=/

      inflated = decode_saml_request_payload(unauth_url)

      assert_match /^<samlp:LogoutRequest/, inflated
    end

    should "support additional params" do

      unauth_url = Onelogin::Saml::Logoutrequest.new.create(settings, { :hello => nil })
      assert unauth_url =~ /&hello=$/

      unauth_url = Onelogin::Saml::Logoutrequest.new.create(settings, { :foo => "bar" })
      assert unauth_url =~ /&foo=bar$/
    end

    should "set sessionindex" do
      settings.idp_slo_target_url = "http://example.com"
      sessionidx = UUID.new.generate
      settings.sessionindex = sessionidx

      unauth_url = Onelogin::Saml::Logoutrequest.new.create(settings, { :name_id => "there" })
      inflated = decode_saml_request_payload(unauth_url)

      assert_match /<samlp:SessionIndex/, inflated
      assert_match %r(#{sessionidx}</samlp:SessionIndex>), inflated
    end

    should "set name_identifier_value" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_slo_target_url = "http://example.com"
      settings.name_identifier_format = "transient"
      name_identifier_value = "abc123"
      settings.name_identifier_value = name_identifier_value

      unauth_url = Onelogin::Saml::Logoutrequest.new.create(settings, { :name_id => "there" })
      inflated = decode_saml_request_payload(unauth_url)

      assert_match /<saml:NameID/, inflated
      assert_match %r(#{name_identifier_value}</saml:NameID>), inflated
    end

    should "require name_identifier_value" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_slo_target_url = "http://example.com"
      settings.name_identifier_format = nil

      assert_raises(Onelogin::Saml::ValidationError) { Onelogin::Saml::Logoutrequest.new.create(settings) }
    end

    context "when the target url doesn't contain a query string" do
      should "create the SAMLRequest parameter correctly" do
        settings = Onelogin::Saml::Settings.new
        settings.idp_slo_target_url = "http://example.com"
        settings.name_identifier_value = "f00f00"

        unauth_url = Onelogin::Saml::Logoutrequest.new.create(settings)
        assert unauth_url =~ /^http:\/\/example.com\?SAMLRequest/
      end
    end

    context "when the target url contains a query string" do
      should "create the SAMLRequest parameter correctly" do
        settings = Onelogin::Saml::Settings.new
        settings.idp_slo_target_url = "http://example.com?field=value"
        settings.name_identifier_value = "f00f00"

        unauth_url = Onelogin::Saml::Logoutrequest.new.create(settings)
        assert unauth_url =~ /^http:\/\/example.com\?field=value&SAMLRequest/
      end
    end

    context "consumation of logout may need to track the transaction" do
      should "have access to the request uuid" do
        settings = Onelogin::Saml::Settings.new
        settings.idp_slo_target_url = "http://example.com?field=value"
        settings.name_identifier_value = "f00f00"

        unauth_req = Onelogin::Saml::Logoutrequest.new
        unauth_url = unauth_req.create(settings)

        inflated = decode_saml_request_payload(unauth_url)
        assert_match %r[ID='#{unauth_req.uuid}'], inflated
      end
    end
  end

  def decode_saml_request_payload(unauth_url)
    payload = CGI.unescape(unauth_url.split("SAMLRequest=").last)
    decoded = Base64.decode64(payload)

    zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    inflated = zstream.inflate(decoded)
    zstream.finish
    zstream.close
    inflated
  end

end

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class SloLogoutresponseTest < Test::Unit::TestCase

  context "SloLogoutresponse" do
    settings = OneLogin::RubySaml::Settings.new

    should "create the deflated SAMLResponse URL parameter" do
      settings.idp_slo_target_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"
      settings.compress_request = true

      request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)

      assert request.is_valid?

      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, request.id)
      assert unauth_url =~ /^http:\/\/unauth\.com\/logout\?SAMLResponse=/

      inflated = decode_saml_response_payload(unauth_url)

      assert_match /^<samlp:LogoutResponse/, inflated
    end

    should "support additional params" do
      settings.idp_slo_target_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"
      settings.compress_request = true

      request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)

      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, request.id, nil, { :hello => nil })
      assert unauth_url =~ /&hello=$/

      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, request.id, nil, { :foo => "bar" })
      assert unauth_url =~ /&foo=bar$/

      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, request.id, nil, { :RelayState => "http://idp.example.com" })
      assert unauth_url =~ /&RelayState=http%3A%2F%2Fidp.example.com$/
    end

    should "set InResponseTo to the ID from the logout request" do
      settings.idp_slo_target_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"
      settings.compress_request = true

      request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, request.id)

      inflated = decode_saml_response_payload(unauth_url)

      assert_match /InResponseTo='_c0348950-935b-0131-1060-782bcb56fcaa'/, inflated
    end

    should "set a custom successful logout message on the response" do
      settings.idp_slo_target_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"
      settings.compress_request = true

      request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, request.id, "Custom Logout Message")

      inflated = decode_saml_response_payload(unauth_url)

      assert_match /<samlp:StatusMessage>Custom Logout Message<\/samlp:StatusMessage>/, inflated
    end

  end

  def decode_saml_response_payload(unauth_url)
    payload = CGI.unescape(unauth_url.split("SAMLResponse=").last)
    decoded = Base64.decode64(payload)

    zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    inflated = zstream.inflate(decoded)
    zstream.finish
    zstream.close
    inflated
  end

end

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

    context "when the settings indicate to sign (embebed) the logout response" do
      should "create a signed logout response" do
        settings = OneLogin::RubySaml::Settings.new
        settings.compress_response = false
        settings.idp_slo_target_url = "http://example.com?field=value"
        settings.security[:logout_responses_signed] = true
        settings.security[:embed_sign] = true
        settings.certificate  = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text

        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings, request.id, "Custom Logout Message")

        response_xml = Base64.decode64(params["SAMLResponse"])
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], response_xml
        response_xml =~ /<ds:SignatureMethod Algorithm='http:\/\/www.w3.org\/2000\/09\/xmldsig#rsa-sha1'\/>/
        response_xml =~ /<ds:DigestMethod Algorithm='http:\/\/www.w3.org\/2000\/09\/xmldsig#rsa-sha1'\/>/
      end

      should "create a signed logout response with 256 digest and signature methods" do
        settings = OneLogin::RubySaml::Settings.new
        settings.compress_response = false
        settings.idp_slo_target_url = "http://example.com?field=value"
        settings.security[:logout_responses_signed] = true
        settings.security[:embed_sign] = true
        settings.security[:signature_method] = XMLSecurity::Document::SHA256
        settings.security[:digest_method] = XMLSecurity::Document::SHA512
        settings.certificate  = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text

        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings, request.id, "Custom Logout Message")

        response_xml = Base64.decode64(params["SAMLResponse"])
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], response_xml
        response_xml =~ /<ds:SignatureMethod Algorithm='http:\/\/www.w3.org\/2001\/04\/xmldsig-more#rsa-sha256'\/>/
        response_xml =~ /<ds:DigestMethod Algorithm='http:\/\/www.w3.org\/2001\/04\/xmldsig-more#rsa-sha512'\/>/
      end
    end

    context "when the settings indicate to sign the logout response" do
      should "create a signature parameter" do
        settings = OneLogin::RubySaml::Settings.new
        settings.compress_response = false
        settings.idp_slo_target_url = "http://example.com?field=value"
        settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
        settings.security[:logout_responses_signed] = true
        settings.security[:embed_sign] = false
        settings.security[:signature_method] = XMLSecurity::Document::SHA1
        settings.certificate  = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text

        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings, request.id, "Custom Logout Message")
        assert params['Signature']
        assert params['SigAlg'] == XMLSecurity::Document::SHA1

        # signature_method only affects the embedeed signature
        settings.security[:signature_method] = XMLSecurity::Document::SHA256
        params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings, request.id, "Custom Logout Message")
        assert params['Signature']
        assert params['SigAlg'] == XMLSecurity::Document::SHA1
      end
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

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/slo_logoutresponse'

class SloLogoutresponseTest < Minitest::Test

  describe "SloLogoutresponse" do
    let(:settings) { OneLogin::RubySaml::Settings.new }
    let(:logout_request) { OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document) }

    before do
      settings.idp_entity_id = 'https://app.onelogin.com/saml/metadata/SOMEACCOUNT'
      settings.idp_slo_target_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"
      settings.compress_request = true
      logout_request.settings = settings
    end

    it "create the deflated SAMLResponse URL parameter" do
      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, logout_request.id)
      assert_match /^http:\/\/unauth\.com\/logout\?SAMLResponse=/, unauth_url
      inflated = decode_saml_response_payload(unauth_url)
      assert_match /^<samlp:LogoutResponse/, inflated
    end

    it "support additional params" do
      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { :hello => nil })
      assert_match /&hello=$/, unauth_url

      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { :foo => "bar" })
      assert_match /&foo=bar$/, unauth_url

      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { :RelayState => "http://idp.example.com" })
      assert_match /&RelayState=http%3A%2F%2Fidp.example.com$/, unauth_url
    end

    it "set InResponseTo to the ID from the logout request" do
      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, logout_request.id)
      inflated = decode_saml_response_payload(unauth_url)
      assert_match /InResponseTo='_c0348950-935b-0131-1060-782bcb56fcaa'/, inflated
    end

    it "set a custom successful logout message on the response" do
      unauth_url = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, "Custom Logout Message")
      inflated = decode_saml_response_payload(unauth_url)
      assert_match /<samlp:StatusMessage>Custom Logout Message<\/samlp:StatusMessage>/, inflated
    end

    describe "when the settings indicate to sign (embedded) logout response" do
      let(:settings_embed_sign) { OneLogin::RubySaml::Settings.new }

      before do
        settings_embed_sign.compress_response = false
        settings_embed_sign.idp_slo_target_url = "http://example.com?field=value"
        settings_embed_sign.security[:logout_responses_signed] = true
        settings_embed_sign.security[:embed_sign] = true
        settings_embed_sign.certificate  = ruby_saml_cert_text
        settings_embed_sign.private_key = ruby_saml_key_text
      end

      it "create a signed logout response" do
        params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings_embed_sign, logout_request.id, "Custom Logout Message")

        response_xml = Base64.decode64(params["SAMLResponse"])
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], response_xml
        assert_match /<ds:SignatureMethod Algorithm='http:\/\/www.w3.org\/2000\/09\/xmldsig#rsa-sha1'\/>/, response_xml
        assert_match /<ds:DigestMethod Algorithm='http:\/\/www.w3.org\/2000\/09\/xmldsig#sha1'\/>/, response_xml
      end

      it "create a signed logout response with 256 digest and signature methods" do
        settings_embed_sign.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        settings_embed_sign.security[:digest_method] = XMLSecurity::Document::SHA512

        params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings_embed_sign, logout_request.id, "Custom Logout Message")

        response_xml = Base64.decode64(params["SAMLResponse"])
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], response_xml
        assert_match /<ds:SignatureMethod Algorithm='http:\/\/www.w3.org\/2001\/04\/xmldsig-more#rsa-sha256'\/>/, response_xml
        assert_match /<ds:DigestMethod Algorithm='http:\/\/www.w3.org\/2001\/04\/xmldsig-more#sha512'\/>/, response_xml
      end
    end

    describe "#create_params when the settings indicate to sign the logout response" do
      let(:settings_logout_signed) { OneLogin::RubySaml::Settings.new }
      let(:cert)      { OpenSSL::X509::Certificate.new(ruby_saml_cert_text) }

      before do
        settings_logout_signed.compress_response = false
        settings_logout_signed.idp_slo_target_url = "http://example.com?field=value"
        settings_logout_signed.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
        settings_logout_signed.security[:logout_responses_signed] = true
        settings_logout_signed.security[:embed_sign] = false
        settings_logout_signed.certificate  = ruby_saml_cert_text
        settings_logout_signed.private_key = ruby_saml_key_text
      end

      it "create a signature parameter with RSA_SHA1 and validate it" do
        settings_logout_signed.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

        params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings_logout_signed, logout_request.id, "Custom Logout Message", :RelayState => 'http://example.com')
        assert params['SAMLResponse']
        assert params[:RelayState]
        assert params['Signature']
        assert_equal params['SigAlg'], XMLSecurity::Document::RSA_SHA1

        query_string = "SAMLResponse=#{CGI.escape(params['SAMLResponse'])}"
        query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
        query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

        signature_algorithm = XMLSecurity::BaseDocument.new.algorithm(params['SigAlg'])
        assert_equal signature_algorithm, OpenSSL::Digest::SHA1
        assert cert.public_key.verify(signature_algorithm.new, Base64.decode64(params['Signature']), query_string)
      end

      it "create a signature parameter with RSA_SHA256 and validate it" do
        settings_logout_signed.security[:signature_method] = XMLSecurity::Document::RSA_SHA256

        params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings_logout_signed, logout_request.id, "Custom Logout Message", :RelayState => 'http://example.com')
        assert params['SAMLResponse']
        assert params[:RelayState]
        assert params['Signature']
        assert_equal params['SigAlg'], XMLSecurity::Document::RSA_SHA256

        query_string = "SAMLResponse=#{CGI.escape(params['SAMLResponse'])}"
        query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
        query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

        signature_algorithm = XMLSecurity::BaseDocument.new.algorithm(params['SigAlg'])
        assert_equal signature_algorithm, OpenSSL::Digest::SHA256
        assert cert.public_key.verify(signature_algorithm.new, Base64.decode64(params['Signature']), query_string)
      end

    end
  end
end

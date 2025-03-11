# frozen_string_literal: true

require_relative 'test_helper'
require 'ruby_saml/authrequest'
require 'ruby_saml/setting_error'

class AuthrequestTest < Minitest::Test

  describe "Authrequest" do
    let(:settings) { RubySaml::Settings.new }

    before do
      settings.idp_sso_service_url = "http://example.com"
    end

    it "create the deflated SAMLRequest URL parameter" do
      auth_url = RubySaml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match(/^<samlp:AuthnRequest/, inflated)
    end

    it "create the deflated SAMLRequest URL parameter including the Destination" do
      auth_url = RubySaml::Authrequest.new.create(settings)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match(/<samlp:AuthnRequest[^<]* Destination="http:\/\/example\.com"/, inflated)
    end

    it "create the SAMLRequest URL parameter without deflating" do
      settings.idp_sso_service_binding = RubySaml::Utils::BINDINGS[:post]
      auth_url = RubySaml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      assert_match(/^<samlp:AuthnRequest/, decoded)
    end

    it "create the SAMLRequest URL parameter with IsPassive" do
      settings.passive = true
      auth_url = RubySaml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match(/<samlp:AuthnRequest[^<]* IsPassive="true"/, inflated)
    end

    it "create the SAMLRequest URL parameter with ProtocolBinding" do
      settings.protocol_binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      auth_url = RubySaml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match(/<samlp:AuthnRequest[^<]* ProtocolBinding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"/, inflated)
    end

    it "create the SAMLRequest URL parameter with AttributeConsumingServiceIndex" do
      settings.attributes_index = 30
      auth_url = RubySaml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close
      assert_match(/<samlp:AuthnRequest[^<]* AttributeConsumingServiceIndex="30"/, inflated)
    end

    it "create the SAMLRequest URL parameter with ForceAuthn" do
      settings.force_authn = true
      auth_url = RubySaml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close
      assert_match(/<samlp:AuthnRequest[^<]* ForceAuthn="true"/, inflated)
    end

    it "create the SAMLRequest URL parameter with NameID Format" do
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      auth_url = RubySaml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
      payload = CGI.unescape(auth_url.split("=").last)
      decoded = Base64.decode64(payload)
      zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match(/<samlp:NameIDPolicy[^<]* AllowCreate="true"/, inflated)
      assert_match(/<samlp:NameIDPolicy[^<]* Format="urn:oasis:names:tc:SAML:2\.0:nameid-format:transient"/, inflated)
    end

    it "create the SAMLRequest URL parameter with Subject" do
      settings.name_identifier_value_requested = "testuser@example.com"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      auth_url = RubySaml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
      payload = CGI.unescape(auth_url.split("=").last)
      decoded = Base64.decode64(payload)
      zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert inflated.include?('<saml:Subject>')
      assert inflated.include?('<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameID>')
      assert inflated.include?('<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>')
    end

    it "accept extra parameters" do
      auth_url = RubySaml::Authrequest.new.create(settings, { :hello => "there" })
      assert_match(/&hello=there$/, auth_url)

      auth_url = RubySaml::Authrequest.new.create(settings, { :hello => nil })
      assert_match(/&hello=$/, auth_url)
    end

    it "RelayState cases" do
      auth_url = RubySaml::Authrequest.new.create(settings, { :RelayState => nil })
      assert !auth_url.include?('RelayState')

      auth_url = RubySaml::Authrequest.new.create(settings, { :RelayState => "http://example.com" })
      assert auth_url.include?('&RelayState=http%3A%2F%2Fexample.com')

      auth_url = RubySaml::Authrequest.new.create(settings, { 'RelayState' => nil })
      assert !auth_url.include?('RelayState')

      auth_url = RubySaml::Authrequest.new.create(settings, { 'RelayState' => "http://example.com" })
      assert auth_url.include?('&RelayState=http%3A%2F%2Fexample.com')
    end

    describe "uuid" do
      it "uuid is initialized to nil" do
        request = RubySaml::Authrequest.new

        assert_nil request.uuid
        assert_nil request.request_id
      end

      it "creates request with ID prefixed with default '_'" do
        request = RubySaml::Authrequest.new
        request.create(settings)

        assert_match(/^_/, request.uuid)
        assert_equal request.uuid, request.request_id
      end

      it "does not change even after repeated #create calls" do
        request = RubySaml::Authrequest.new
        request.create(settings)

        uuid = request.uuid
        request.create(settings)

        assert_equal uuid, request.uuid
        assert_equal request.uuid, request.request_id
      end

      it "creates request with ID prefixed by Settings#sp_uuid_prefix" do
        settings.sp_uuid_prefix = 'test'
        request = RubySaml::Authrequest.new
        request.create(settings)

        assert_match(/^test/, request.uuid)
        assert_equal request.uuid, request.request_id
      end

      it "can mutate the uuid" do
        request = RubySaml::Authrequest.new
        assert_nil request.uuid
        assert_nil request.request_id

        request.uuid = "new_uuid"
        assert_equal "new_uuid", request.uuid
        assert_equal request.uuid, request.request_id
      end
    end

    describe "when the target url is not set" do
      before do
        settings.idp_sso_service_url = nil
      end

      it "raises an error with a descriptive message" do
        err = assert_raises RubySaml::SettingError do
          RubySaml::Authrequest.new.create(settings)
        end
        assert_match(/idp_sso_service_url is not set/, err.message)
      end
    end

    describe "when the target url doesn't contain a query string" do
      it "create the SAMLRequest parameter correctly" do

        auth_url = RubySaml::Authrequest.new.create(settings)
        assert_match(/^http:\/\/example\.com\?SAMLRequest/, auth_url)
      end
    end

    describe "when the target url contains a query string" do
      it "create the SAMLRequest parameter correctly" do
        settings.idp_sso_service_url = "http://example.com?field=value"

        auth_url = RubySaml::Authrequest.new.create(settings)
        assert_match(/^http:\/\/example\.com\?field=value&SAMLRequest/, auth_url)
      end
    end

    it "create the saml:AuthnContextClassRef element correctly" do
      settings.authn_context = 'secure/name/password/uri'
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert_match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
    end

    it "create multiple saml:AuthnContextClassRef elements correctly" do
      settings.authn_context = ['secure/name/password/uri', 'secure/email/password/uri']
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert_match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
      assert_match(/<saml:AuthnContextClassRef>secure\/email\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
    end

    it "create the saml:AuthnContextClassRef with comparison exact" do
      settings.authn_context = 'secure/name/password/uri'
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert_match(/<samlp:RequestedAuthnContext[\S ]+Comparison="exact"/, auth_doc.to_s)
      assert_match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
    end

    it "create the saml:AuthnContextClassRef with comparison minimun" do
      settings.authn_context = 'secure/name/password/uri'
      settings.authn_context_comparison = 'minimun'
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert_match(/<samlp:RequestedAuthnContext[\S ]+Comparison="minimun"/, auth_doc.to_s)
      assert_match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
    end

    it "create the saml:AuthnContextDeclRef element correctly" do
      settings.authn_context_decl_ref = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert_match(/<saml:AuthnContextDeclRef>urn:oasis:names:tc:SAML:2\.0:ac:classes:PasswordProtectedTransport<\/saml:AuthnContextDeclRef>/, auth_doc.to_s)
    end

    it "create the saml:AuthnContextClassRef element correctly" do
      settings.authn_context = 'secure/name/password/uri'
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    it "create the saml:AuthnContextClassRef with comparison exact" do
      settings.authn_context = 'secure/name/password/uri'
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<samlp:RequestedAuthnContext[\S ]+Comparison="exact"/
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    it "create the saml:AuthnContextClassRef with comparison minimun" do
      settings.authn_context = 'secure/name/password/uri'
      settings.authn_context_comparison = 'minimun'
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<samlp:RequestedAuthnContext[\S ]+Comparison="minimun"/
      assert auth_doc.to_s =~ /<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/
    end

    it "create the saml:AuthnContextDeclRef element correctly" do
      settings.authn_context_decl_ref = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<saml:AuthnContextDeclRef>urn:oasis:names:tc:SAML:2\.0:ac:classes:PasswordProtectedTransport<\/saml:AuthnContextDeclRef>/
    end

    it "create multiple saml:AuthnContextDeclRef elements correctly " do
      settings.authn_context_decl_ref = ['name/password/uri', 'example/decl/ref']
      auth_doc = RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
      assert auth_doc.to_s =~ /<saml:AuthnContextDeclRef>name\/password\/uri<\/saml:AuthnContextDeclRef>/
      assert auth_doc.to_s =~ /<saml:AuthnContextDeclRef>example\/decl\/ref<\/saml:AuthnContextDeclRef>/
    end

    each_signature_algorithm do |sp_key_algo, sp_hash_algo|
      describe "#create_params signing with HTTP-POST binding" do
        before do
          settings.idp_sso_service_url = "http://example.com?field=value"
          settings.idp_sso_service_binding = :post
          settings.security[:authn_requests_signed] = true
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo)
          settings.security[:signature_method] = signature_method(sp_key_algo, sp_hash_algo)
          settings.security[:digest_method] = digest_method(sp_hash_algo)
        end

        it "create a signed request" do
          params = RubySaml::Authrequest.new.create_params(settings)
          request_xml = Base64.decode64(params["SAMLRequest"])

          assert_match(signature_value_matcher, request_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), request_xml)
          assert_match(digest_method_matcher(sp_hash_algo), request_xml)
        end

        unless sp_hash_algo == :sha256
          it 'using mixed signature and digest methods (signature SHA256)' do
            # RSA is ignored here; only the hash sp_key_algo is used
            settings.security[:signature_method] = RubySaml::XML::RSA_SHA256
            params = RubySaml::Authrequest.new.create_params(settings)
            request_xml = Base64.decode64(params["SAMLRequest"])

            assert_match(signature_value_matcher, request_xml)
            assert_match(signature_method_matcher(sp_key_algo, :sha256), request_xml)
            assert_match(digest_method_matcher(sp_hash_algo), request_xml)
          end

          it 'using mixed signature and digest methods (digest SHA256)' do
            settings.security[:digest_method] = RubySaml::XML::SHA256
            params = RubySaml::Authrequest.new.create_params(settings)
            request_xml = Base64.decode64(params["SAMLRequest"])

            assert_match(signature_value_matcher, request_xml)
            assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), request_xml)
            assert_match(digest_method_matcher(:sha256), request_xml)
          end
        end

        it "creates a signed request using the first certificate and key" do
          settings.certificate = nil
          settings.private_key = nil
          settings.sp_cert_multi = {
            signing: [
              CertificateHelper.generate_pem_hash(sp_key_algo),
              CertificateHelper.generate_pem_hash
            ]
          }
          params = RubySaml::Authrequest.new.create_params(settings)
          request_xml = Base64.decode64(params["SAMLRequest"])

          assert_match(signature_value_matcher, request_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), request_xml)
          assert_match(digest_method_matcher(sp_hash_algo), request_xml)
        end

        it "creates a signed request using the first valid certificate and key when :check_sp_cert_expiration is true" do
          settings.certificate = nil
          settings.private_key = nil
          settings.security[:check_sp_cert_expiration] = true
          settings.sp_cert_multi = {
            signing: [
              CertificateHelper.generate_pem_hash(sp_key_algo),
              CertificateHelper.generate_pem_hash
            ]
          }
          params = RubySaml::Authrequest.new.create_params(settings)
          request_xml = Base64.decode64(params["SAMLRequest"])

          assert_match(signature_value_matcher, request_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), request_xml)
          assert_match(digest_method_matcher(sp_hash_algo), request_xml)
        end

        it "raises error when no valid certs and :check_sp_cert_expiration is true" do
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo, not_after: Time.now - 60)
          settings.security[:check_sp_cert_expiration] = true

          assert_raises(RubySaml::ValidationError, 'The SP certificate expired.') do
            RubySaml::Authrequest.new.create_params(settings)
          end
        end
      end
    end

    each_signature_algorithm do |sp_key_algo, sp_hash_algo|
      describe "#create_params signing with HTTP-Redirect binding" do
        let(:cert) { OpenSSL::X509::Certificate.new(ruby_saml_cert_text) }

        before do
          settings.idp_sso_service_url = "http://example.com?field=value"
          settings.idp_sso_service_binding = :redirect
          settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
          settings.security[:authn_requests_signed] = true
          @cert, @pkey = CertificateHelper.generate_pair(sp_key_algo)
          settings.certificate, settings.private_key = [@cert, @pkey].map(&:to_pem)
          settings.security[:signature_method] = signature_method(sp_key_algo, sp_hash_algo)
          settings.security[:digest_method] = digest_method(sp_hash_algo)
        end

        it "create a signature parameter and validate it" do
          params = RubySaml::Authrequest.new.create_params(settings, :RelayState => 'http://example.com')

          assert params['SAMLRequest']
          assert params[:RelayState]
          assert params['Signature']
          assert_equal params['SigAlg'], signature_method(sp_key_algo, sp_hash_algo)

          query_string = "SAMLRequest=#{CGI.escape(params['SAMLRequest'])}"
          query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
          query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

          assert @cert.public_key.verify(RubySaml::XML.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
        end

        unless sp_hash_algo == :sha256
          it 'using mixed signature and digest methods (signature SHA256)' do
            # RSA is ignored here; only the hash sp_key_algo is used
            settings.security[:signature_method] = RubySaml::XML::RSA_SHA256
            params = RubySaml::Authrequest.new.create_params(settings, :RelayState => 'http://example.com')

            assert params['SAMLRequest']
            assert params[:RelayState]
            assert params['Signature']
            assert_equal params['SigAlg'], signature_method(sp_key_algo, :sha256)

            query_string = "SAMLRequest=#{CGI.escape(params['SAMLRequest'])}"
            query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
            query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

            assert @cert.public_key.verify(RubySaml::XML.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
          end

          it 'using mixed signature and digest methods (digest SHA256)' do
            settings.security[:digest_method] = RubySaml::XML::SHA256
            params = RubySaml::Authrequest.new.create_params(settings, :RelayState => 'http://example.com')

            assert params['SAMLRequest']
            assert params[:RelayState]
            assert params['Signature']
            assert_equal params['SigAlg'], signature_method(sp_key_algo, sp_hash_algo)

            query_string = "SAMLRequest=#{CGI.escape(params['SAMLRequest'])}"
            query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
            query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

            assert @cert.public_key.verify(RubySaml::XML.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
          end
        end

        it "create a signature parameter using the first certificate and key" do
          settings.security[:signature_method] = RubySaml::XML::RSA_SHA1
          settings.certificate = nil
          settings.private_key = nil
          cert, pkey = CertificateHelper.generate_pair(sp_key_algo)
          settings.sp_cert_multi = {
            signing: [
              { certificate: cert.to_pem, private_key: pkey.to_pem },
              CertificateHelper.generate_pem_hash
            ]
          }

          params = RubySaml::Authrequest.new.create_params(settings, :RelayState => 'http://example.com')
          assert params['SAMLRequest']
          assert params[:RelayState]
          assert params['Signature']
          assert_equal params['SigAlg'], signature_method(sp_key_algo, :sha1)

          query_string = "SAMLRequest=#{CGI.escape(params['SAMLRequest'])}"
          query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
          query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

          signature_algorithm = RubySaml::XML.hash_algorithm(params['SigAlg'])
          assert_equal signature_algorithm, OpenSSL::Digest::SHA1
          assert cert.public_key.verify(signature_algorithm.new, Base64.decode64(params['Signature']), query_string)
        end

        it "raises error when no valid certs and :check_sp_cert_expiration is true" do
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo, not_after: Time.now - 60)
          settings.security[:check_sp_cert_expiration] = true

          assert_raises(RubySaml::ValidationError, 'The SP certificate expired.') do
            RubySaml::Authrequest.new.create_params(settings, :RelayState => 'http://example.com')
          end
        end
      end
    end
  end
end

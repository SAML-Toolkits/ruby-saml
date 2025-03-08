require_relative 'test_helper'

require 'ruby_saml/logoutrequest'

class RequestTest < Minitest::Test

  describe "Logoutrequest" do
    let(:settings) { RubySaml::Settings.new }

    before do
      settings.idp_slo_service_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"
    end

    it "creates the deflated SAMLRequest URL parameter" do
      unauth_url = RubySaml::Logoutrequest.new.create(settings)
      assert_match(/^http:\/\/unauth\.com\/logout\?SAMLRequest=/, unauth_url)

      inflated = decode_saml_request_payload(unauth_url)
      assert_match(/^<samlp:LogoutRequest/, inflated)
    end

    it "support additional params" do
      unauth_url = RubySaml::Logoutrequest.new.create(settings, { :hello => nil })
      assert_match(/&hello=$/, unauth_url)

      unauth_url = RubySaml::Logoutrequest.new.create(settings, { :foo => "bar" })
      assert_match(/&foo=bar$/, unauth_url)
    end

    it "RelayState cases" do
      unauth_url = RubySaml::Logoutrequest.new.create(settings, { :RelayState => nil })
      assert !unauth_url.include?('RelayState')

      unauth_url = RubySaml::Logoutrequest.new.create(settings, { :RelayState => "http://example.com" })
      assert unauth_url.include?('&RelayState=http%3A%2F%2Fexample.com')

      unauth_url = RubySaml::Logoutrequest.new.create(settings, { 'RelayState' => nil })
      assert !unauth_url.include?('RelayState')

      unauth_url = RubySaml::Logoutrequest.new.create(settings, { 'RelayState' => "http://example.com" })
      assert unauth_url.include?('&RelayState=http%3A%2F%2Fexample.com')
    end

    it "set sessionindex" do
      settings.idp_slo_service_url = "http://example.com"
      sessionidx = RubySaml::Utils.uuid
      settings.sessionindex = sessionidx

      unauth_url = RubySaml::Logoutrequest.new.create(settings, { :nameid => "there" })
      inflated = decode_saml_request_payload(unauth_url)

      assert_match(/<samlp:SessionIndex/, inflated)
      assert_match %r(#{sessionidx}</samlp:SessionIndex>), inflated
    end

    it "set name_identifier_value" do
      settings.name_identifier_format = "transient"
      name_identifier_value = "abc123"
      settings.name_identifier_value = name_identifier_value

      unauth_url = RubySaml::Logoutrequest.new.create(settings, { :nameid => "there" })
      inflated = decode_saml_request_payload(unauth_url)

      assert_match(/<saml:NameID/, inflated)
      assert_match %r(#{name_identifier_value}</saml:NameID>), inflated
    end

    describe "when the target url doesn't contain a query string" do
      it "creates the SAMLRequest parameter correctly" do
        unauth_url = RubySaml::Logoutrequest.new.create(settings)
        assert_match(/^http:\/\/unauth.com\/logout\?SAMLRequest/, unauth_url)
      end
    end

    describe "when the target url contains a query string" do
      it "creates the SAMLRequest parameter correctly" do
        settings.idp_slo_service_url = "http://example.com?field=value"

        unauth_url = RubySaml::Logoutrequest.new.create(settings)
        assert_match(/^http:\/\/example\.com\?field=value&SAMLRequest/, unauth_url)
      end
    end

    describe "consumation of logout may need to track the transaction" do
      it "have access to the request uuid" do
        settings.idp_slo_service_url = "http://example.com?field=value"

        unauth_req = RubySaml::Logoutrequest.new
        unauth_url = unauth_req.create(settings)

        inflated = decode_saml_request_payload(unauth_url)
        assert_match %r[ID="#{unauth_req.uuid}"], inflated
      end
    end

    describe "uuid" do
      it "uuid is initialized to nil" do
        request = RubySaml::Logoutrequest.new

        assert_nil request.uuid
        assert_nil request.request_id
      end

      it "creates request with ID prefixed with default '_'" do
        request = RubySaml::Logoutrequest.new
        request.create(settings)

        assert_match(/^_/, request.uuid)
        assert_equal request.uuid, request.request_id
      end

      it "does not change even after repeated #create calls" do
        request = RubySaml::Logoutrequest.new
        request.create(settings)

        uuid = request.uuid
        request.create(settings)

        assert_equal uuid, request.uuid
        assert_equal request.uuid, request.request_id
      end

      it "creates request with ID prefixed by Settings#sp_uuid_prefix" do
        settings.sp_uuid_prefix = 'test'
        request = RubySaml::Logoutrequest.new
        request.create(settings)

        assert_match(/^test/, request.uuid)
        assert_equal request.uuid, request.request_id
      end

      it "can mutate the uuid" do
        request = RubySaml::Logoutrequest.new
        assert_nil request.uuid
        assert_nil request.request_id

        request.uuid = "new_uuid"
        assert_equal "new_uuid", request.uuid
        assert_equal request.uuid, request.request_id
      end
    end

    each_signature_algorithm do |sp_key_algo, sp_hash_algo|
      describe 'signing with HTTP-POST binding' do
        before do
          settings.idp_slo_service_binding = :post
          settings.idp_sso_service_binding = :redirect
          settings.security[:logout_requests_signed] = true
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo)
          settings.security[:signature_method] = signature_method(sp_key_algo, sp_hash_algo)
          settings.security[:digest_method] = digest_method(sp_hash_algo)
        end

        it "doesn't sign through create_xml_document" do
          unauth_req = RubySaml::Logoutrequest.new
          inflated = unauth_req.create_xml_document(settings).to_s

          refute_match(/<ds:SignatureValue/, inflated)
          refute_match(/<ds:SignatureMethod/, inflated)
          refute_match(/<ds:DigestMethod/, inflated)
        end

        it "signs an unsigned request" do
          unauth_req = RubySaml::Logoutrequest.new
          unauth_req_doc = unauth_req.create_xml_document(settings)
          inflated = unauth_req_doc.to_s

          refute_match(/<ds:SignatureValue/, inflated)
          refute_match(/<ds:SignatureMethod/, inflated)
          refute_match(/<ds:DigestMethod/, inflated)

          inflated = unauth_req.sign_document(unauth_req_doc, settings).to_s

          assert_match(signature_value_matcher, inflated)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), inflated)
          assert_match(digest_method_matcher(sp_hash_algo), inflated)
        end

        it "signs through create_logout_request_xml_doc" do
          unauth_req = RubySaml::Logoutrequest.new
          inflated = unauth_req.create_logout_request_xml_doc(settings).to_s

          assert_match(signature_value_matcher, inflated)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), inflated)
          assert_match(digest_method_matcher(sp_hash_algo), inflated)
        end

        it "creates a signed logout request" do
          params = RubySaml::Logoutrequest.new.create_params(settings)
          request_xml = Base64.decode64(params["SAMLRequest"])

          assert_match(signature_value_matcher, request_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), request_xml)
          assert_match(digest_method_matcher(sp_hash_algo), request_xml)
        end

        unless sp_hash_algo == :sha256
          it 'using mixed signature and digest methods (signature SHA256)' do
            # RSA is ignored here; only the hash sp_key_algo is used
            settings.security[:signature_method] = RubySaml::XML::Crypto::RSA_SHA256
            params = RubySaml::Logoutrequest.new.create_params(settings)
            request_xml = Base64.decode64(params["SAMLRequest"])

            assert_match(signature_value_matcher, request_xml)
            assert_match(signature_method_matcher(sp_key_algo, :sha256), request_xml)
            assert_match(digest_method_matcher(sp_hash_algo), request_xml)
          end

          it 'using mixed signature and digest methods (digest SHA256)' do
            settings.security[:digest_method] = RubySaml::XML::Crypto::SHA256
            params = RubySaml::Logoutrequest.new.create_params(settings)
            request_xml = Base64.decode64(params["SAMLRequest"])

            assert_match(signature_value_matcher, request_xml)
            assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), request_xml)
            assert_match(digest_method_matcher(:sha256), request_xml)
          end
        end

        it "creates a signed logout request using the first certificate and key" do
          settings.certificate = nil
          settings.private_key = nil
          settings.sp_cert_multi = {
            signing: [
              CertificateHelper.generate_pem_hash(sp_key_algo),
              CertificateHelper.generate_pem_hash
            ]
          }
          params = RubySaml::Logoutrequest.new.create_params(settings)
          request_xml = Base64.decode64(params["SAMLRequest"])

          assert_match(signature_value_matcher, request_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), request_xml)
          assert_match(digest_method_matcher(sp_hash_algo), request_xml)
        end

        it "creates a signed logout request using the first valid certificate and key when :check_sp_cert_expiration is true" do
          settings.certificate = nil
          settings.private_key = nil
          settings.security[:check_sp_cert_expiration] = true
          settings.sp_cert_multi = {
            signing: [
              CertificateHelper.generate_pem_hash(sp_key_algo),
              CertificateHelper.generate_pem_hash
            ]
          }
          params = RubySaml::Logoutrequest.new.create_params(settings)
          request_xml = Base64.decode64(params["SAMLRequest"])

          assert_match(signature_value_matcher, request_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), request_xml)
          assert_match(digest_method_matcher(sp_hash_algo), request_xml)
        end

        it "raises error when no valid certs and :check_sp_cert_expiration is true" do
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo, not_after: Time.now - 60)
          settings.security[:check_sp_cert_expiration] = true

          assert_raises(RubySaml::ValidationError, 'The SP certificate expired.') do
            RubySaml::Logoutrequest.new.create_params(settings)
          end
        end
      end
    end

    each_signature_algorithm do |sp_key_algo, sp_hash_algo|
      describe 'signing with HTTP-Redirect binding' do
        before do
          settings.idp_slo_service_binding = :redirect
          settings.idp_sso_service_binding = :post
          settings.security[:logout_requests_signed] = true
          @cert, @pkey = CertificateHelper.generate_pair(sp_key_algo)
          settings.certificate, settings.private_key = [@cert, @pkey].map(&:to_pem)
          settings.security[:signature_method] = signature_method(sp_key_algo, sp_hash_algo)
          settings.security[:digest_method] = digest_method(sp_hash_algo)
        end

        it "creates a signature parameter and validate it" do
          params = RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')

          assert params['SAMLRequest']
          assert params[:RelayState]
          assert params['Signature']
          assert_equal params['SigAlg'], signature_method(sp_key_algo, sp_hash_algo)

          query_string = "SAMLRequest=#{CGI.escape(params['SAMLRequest'])}"
          query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
          query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

          assert @cert.public_key.verify(RubySaml::XML::Crypto.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
        end

        unless sp_hash_algo == :sha256
          it 'using mixed signature and digest methods (signature SHA256)' do
            # RSA is ignored here; only the hash sp_key_algo is used
            settings.security[:signature_method] = RubySaml::XML::Crypto::RSA_SHA256
            params = RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')

            assert params['SAMLRequest']
            assert params[:RelayState]
            assert params['Signature']
            assert_equal params['SigAlg'], signature_method(sp_key_algo, :sha256)

            query_string = "SAMLRequest=#{CGI.escape(params['SAMLRequest'])}"
            query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
            query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

            assert @cert.public_key.verify(RubySaml::XML::Crypto.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
          end

          it 'using mixed signature and digest methods (digest SHA256)' do
            settings.security[:digest_method] = RubySaml::XML::Crypto::SHA256
            params = RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')

            assert params['SAMLRequest']
            assert params[:RelayState]
            assert params['Signature']
            assert_equal params['SigAlg'], signature_method(sp_key_algo, sp_hash_algo)

            query_string = "SAMLRequest=#{CGI.escape(params['SAMLRequest'])}"
            query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
            query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

            assert @cert.public_key.verify(RubySaml::XML::Crypto.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
          end
        end

        it "creates a signature parameter using the first certificate and key" do
          settings.certificate = nil
          settings.private_key = nil
          cert, pkey = CertificateHelper.generate_pair(sp_key_algo)
          settings.sp_cert_multi = {
            signing: [
              { certificate: cert.to_pem, private_key: pkey.to_pem },
              CertificateHelper.generate_pem_hash
            ]
          }
          params = RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')

          assert params['SAMLRequest']
          assert params[:RelayState]
          assert params['Signature']
          assert_equal params['SigAlg'], signature_method(sp_key_algo, sp_hash_algo)

          query_string = "SAMLRequest=#{CGI.escape(params['SAMLRequest'])}"
          query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
          query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

          assert cert.public_key.verify(RubySaml::XML::Crypto.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
        end

        it "raises error when no valid certs and :check_sp_cert_expiration is true" do
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo, not_after: Time.now - 60)
          settings.security[:check_sp_cert_expiration] = true

          assert_raises(RubySaml::ValidationError, 'The SP certificate expired.') do
            RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')
          end
        end
      end
    end
  end
end

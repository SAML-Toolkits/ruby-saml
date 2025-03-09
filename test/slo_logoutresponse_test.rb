require_relative 'test_helper'

require 'ruby_saml/slo_logoutresponse'

class SloLogoutresponseTest < Minitest::Test

  describe "SloLogoutresponse" do
    let(:settings) { RubySaml::Settings.new }
    let(:logout_request) { RubySaml::SloLogoutrequest.new(logout_request_document) }

    before do
      settings.idp_entity_id = 'https://app.onelogin.com/saml/metadata/SOMEACCOUNT'
      settings.idp_slo_service_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"
      settings.certificate = ruby_saml_cert_text
      settings.private_key = ruby_saml_key_text
      logout_request.settings = settings
    end

    it "creates the deflated SAMLResponse URL parameter" do
      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id)
      assert_match(/^http:\/\/unauth\.com\/logout\?SAMLResponse=/, unauth_url)

      inflated = decode_saml_response_payload(unauth_url)
      assert_match(/^<samlp:LogoutResponse/, inflated)
    end

    it "support additional params" do
      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { :hello => nil })
      assert_match(/&hello=$/, unauth_url)

      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { :foo => "bar" })
      assert_match(/&foo=bar$/, unauth_url)

      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { :RelayState => "http://idp.example.com" })
      assert_match(/&RelayState=http%3A%2F%2Fidp.example.com$/, unauth_url)
    end

    it "RelayState cases" do
      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { :RelayState => nil })
      assert !unauth_url.include?('RelayState')

      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { :RelayState => "http://example.com" })
      assert unauth_url.include?('&RelayState=http%3A%2F%2Fexample.com')

      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { 'RelayState' => nil })
      assert !unauth_url.include?('RelayState')

      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, nil, { 'RelayState' => "http://example.com" })
      assert unauth_url.include?('&RelayState=http%3A%2F%2Fexample.com')
    end

    it "set InResponseTo to the ID from the logout request" do
      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id)

      inflated = decode_saml_response_payload(unauth_url)
      assert_match(/InResponseTo="_c0348950-935b-0131-1060-782bcb56fcaa"/, inflated)
    end

    it "set a custom successful logout message on the response" do
      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id, "Custom Logout Message")

      inflated = decode_saml_response_payload(unauth_url)
      assert_match(/<samlp:StatusMessage>Custom Logout Message<\/samlp:StatusMessage>/, inflated)
    end

    it "set a custom logout message and an status on the response" do
      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, nil, "Custom Logout Message", {}, "urn:oasis:names:tc:SAML:2.0:status:PartialLogout")

      inflated = decode_saml_response_payload(unauth_url)
      assert_match(/<samlp:StatusMessage>Custom Logout Message<\/samlp:StatusMessage>/, inflated)
      assert_match(/<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2\.0:status:PartialLogout/, inflated)
    end

    it "uses the response location when set" do
      settings.idp_slo_response_service_url = "http://unauth.com/logout/return"

      unauth_url = RubySaml::SloLogoutresponse.new.create(settings, logout_request.id)
      assert_match(/^http:\/\/unauth\.com\/logout\/return\?SAMLResponse=/, unauth_url)

      inflated = decode_saml_response_payload(unauth_url)
      assert_match(/Destination="http:\/\/unauth\.com\/logout\/return"/, inflated)
    end

    describe "uuid" do
      it "uuid is initialized to nil" do
        response = RubySaml::SloLogoutresponse.new

        assert_nil response.uuid
        assert_nil response.response_id
      end

      it "creates response with ID prefixed with default '_'" do
        response = RubySaml::SloLogoutresponse.new
        response.create(settings)

        assert_match(/^_/, response.uuid)
        assert_equal response.uuid, response.response_id
      end

      it "does not change even after repeated #create calls" do
        response = RubySaml::SloLogoutresponse.new
        response.create(settings)

        uuid = response.uuid
        response.create(settings)

        assert_equal uuid, response.uuid
        assert_equal response.uuid, response.response_id
      end

      it "creates response with ID prefixed by Settings#sp_uuid_prefix" do
        settings.sp_uuid_prefix = 'test'
        response = RubySaml::SloLogoutresponse.new
        response.create(settings)

        assert_match(/^test/, response.uuid)
        assert_equal response.uuid, response.response_id
      end

      it "can mutate the uuid" do
        response = RubySaml::SloLogoutresponse.new
        assert_nil response.uuid
        assert_nil response.response_id

        response.uuid = "new_uuid"
        assert_equal "new_uuid", response.uuid
        assert_equal response.uuid, response.response_id
      end
    end

    each_signature_algorithm do |sp_key_algo, sp_hash_algo|
      describe 'signing with HTTP-POST binding' do
        before do
          settings.idp_sso_service_binding = :redirect
          settings.idp_slo_service_binding = :post
          settings.security[:logout_responses_signed] = true
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo)
          settings.security[:signature_method] = signature_method(sp_key_algo, sp_hash_algo)
          settings.security[:digest_method] = digest_method(sp_hash_algo)
        end

        it "doesn't sign through create_xml_document" do
          unauth_res = RubySaml::SloLogoutresponse.new
          inflated = unauth_res.create_xml_document(settings).to_s

          refute_match(/<ds:SignatureValue/, inflated)
          refute_match(/<ds:SignatureMethod/, inflated)
          refute_match(/<ds:DigestMethod/, inflated)
        end

        it "signs an unsigned request" do
          unauth_res = RubySaml::SloLogoutresponse.new
          unauth_res_doc = unauth_res.create_xml_document(settings)
          inflated = unauth_res_doc.to_s

          refute_match(/<ds:SignatureValue/, inflated)
          refute_match(/<ds:SignatureMethod/, inflated)
          refute_match(/<ds:DigestMethod/, inflated)

          inflated = unauth_res.sign_document(unauth_res_doc, settings).to_s

          assert_match(signature_value_matcher, inflated)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), inflated)
          assert_match(digest_method_matcher(sp_hash_algo), inflated)
        end

        it "signs through create_logout_response_xml_doc" do
          unauth_res = RubySaml::SloLogoutresponse.new
          inflated = unauth_res.create_logout_response_xml_doc(settings).to_s

          assert_match(signature_value_matcher, inflated)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), inflated)
          assert_match(digest_method_matcher(sp_hash_algo), inflated)
        end

        it "creates a signed logout response" do
          logout_request.settings = settings
          params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message")
          response_xml = Base64.decode64(params["SAMLResponse"])

          assert_match(signature_value_matcher, response_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), response_xml)
          assert_match(digest_method_matcher(sp_hash_algo), response_xml)
        end

        unless sp_hash_algo == :sha256
          it 'using mixed signature and digest methods (signature SHA256)' do
            # RSA is ignored here; only the hash sp_key_algo is used
            settings.security[:signature_method] = RubySaml::XML::RSA_SHA256
            logout_request.settings = settings
            params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message")
            response_xml = Base64.decode64(params["SAMLResponse"])

            assert_match(signature_value_matcher, response_xml)
            assert_match(signature_method_matcher(sp_key_algo, :sha256), response_xml)
            assert_match(digest_method_matcher(sp_hash_algo), response_xml)
          end

          it 'using mixed signature and digest methods (digest SHA256)' do
            settings.security[:digest_method] = RubySaml::XML::SHA256
            logout_request.settings = settings
            params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message")
            response_xml = Base64.decode64(params["SAMLResponse"])

            assert_match(signature_value_matcher, response_xml)
            assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), response_xml)
            assert_match(digest_method_matcher(:sha256), response_xml)
          end
        end

        it "creates a signed logout response using the first certificate and key" do
          settings.certificate = nil
          settings.private_key = nil
          settings.sp_cert_multi = {
            signing: [
              CertificateHelper.generate_pem_hash(sp_key_algo),
              CertificateHelper.generate_pem_hash
            ]
          }
          logout_request.settings = settings
          params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message")
          response_xml = Base64.decode64(params["SAMLResponse"])

          assert_match(signature_value_matcher, response_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), response_xml)
          assert_match(digest_method_matcher(sp_hash_algo), response_xml)
        end

        it "creates a signed logout response using the first valid certificate and key when :check_sp_cert_expiration is true" do
          settings.certificate = nil
          settings.private_key = nil
          settings.security[:check_sp_cert_expiration] = true
          settings.sp_cert_multi = {
            signing: [
              CertificateHelper.generate_pem_hash(sp_key_algo),
              CertificateHelper.generate_pem_hash
            ]
          }
          logout_request.settings = settings
          params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message")
          response_xml = Base64.decode64(params["SAMLResponse"])

          assert_match(signature_value_matcher, response_xml)
          assert_match(signature_method_matcher(sp_key_algo, sp_hash_algo), response_xml)
          assert_match(digest_method_matcher(sp_hash_algo), response_xml)
        end

        it "raises error when no valid certs and :check_sp_cert_expiration is true" do
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo, not_after: Time.now - 60)
          settings.security[:check_sp_cert_expiration] = true
          logout_request.settings = settings

          assert_raises(RubySaml::ValidationError, 'The SP certificate expired.') do
            RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message")
          end
        end
      end
    end

    each_signature_algorithm do |sp_key_algo, sp_hash_algo|
      describe 'signing with HTTP-Redirect binding' do
        before do
          settings.idp_sso_service_binding = :post
          settings.idp_slo_service_binding = :redirect
          settings.security[:logout_responses_signed] = true
          @cert, @pkey = CertificateHelper.generate_pair(sp_key_algo)
          settings.certificate, settings.private_key = [@cert, @pkey].map(&:to_pem)
          settings.security[:signature_method] = signature_method(sp_key_algo, sp_hash_algo)
          settings.security[:digest_method] = digest_method(sp_hash_algo)
        end

        it "creates a signature parameter and validate it" do
          params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message", :RelayState => 'http://example.com')

          assert params['SAMLResponse']
          assert params[:RelayState]
          assert params['Signature']
          assert_equal params['SigAlg'], signature_method(sp_key_algo, sp_hash_algo)

          query_string = "SAMLResponse=#{CGI.escape(params['SAMLResponse'])}"
          query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
          query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

          assert @cert.public_key.verify(RubySaml::XML.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
        end

        unless sp_hash_algo == :sha256
          it 'using mixed signature and digest methods (signature SHA256)' do
            # RSA is ignored here; only the hash sp_key_algo is used
            settings.security[:signature_method] = RubySaml::XML::RSA_SHA256
            logout_request.settings = settings
            params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message", :RelayState => 'http://example.com')

            assert params['SAMLResponse']
            assert params[:RelayState]
            assert params['Signature']
            assert_equal params['SigAlg'], signature_method(sp_key_algo, :sha256)

            query_string = "SAMLResponse=#{CGI.escape(params['SAMLResponse'])}"
            query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
            query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

            assert @cert.public_key.verify(RubySaml::XML.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
          end

          it 'using mixed signature and digest methods (digest SHA256)' do
            settings.security[:digest_method] = RubySaml::XML::SHA256
            logout_request.settings = settings
            params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message", :RelayState => 'http://example.com')

            assert params['SAMLResponse']
            assert params[:RelayState]
            assert params['Signature']
            assert_equal params['SigAlg'], signature_method(sp_key_algo, sp_hash_algo)

            query_string = "SAMLResponse=#{CGI.escape(params['SAMLResponse'])}"
            query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
            query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

            assert @cert.public_key.verify(RubySaml::XML.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
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
          params = RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message", :RelayState => 'http://example.com')

          assert params['SAMLResponse']
          assert params[:RelayState]
          assert params['Signature']
          assert_equal params['SigAlg'], signature_method(sp_key_algo, sp_hash_algo)

          query_string = "SAMLResponse=#{CGI.escape(params['SAMLResponse'])}"
          query_string << "&RelayState=#{CGI.escape(params[:RelayState])}"
          query_string << "&SigAlg=#{CGI.escape(params['SigAlg'])}"

          assert cert.public_key.verify(RubySaml::XML.hash_algorithm(params['SigAlg']).new, Base64.decode64(params['Signature']), query_string)
        end

        it "raises error when no valid certs and :check_sp_cert_expiration is true" do
          settings.certificate, settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo, not_after: Time.now - 60)
          settings.security[:check_sp_cert_expiration] = true

          assert_raises(RubySaml::ValidationError, 'The SP certificate expired.') do
            RubySaml::SloLogoutresponse.new.create_params(settings, logout_request.id, "Custom Logout Message", :RelayState => 'http://example.com')
          end
        end
      end
    end
  end
end

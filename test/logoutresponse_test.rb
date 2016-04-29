require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/logoutresponse'
require 'logout_responses/logoutresponse_fixtures'

class RubySamlTest < Minitest::Test

  describe "Logoutresponse" do

    let(:valid_logout_response_without_settings) { OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document) }
    let(:valid_logout_response) { OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document, settings) }

    describe "#new" do
      it "raise an exception when response is initialized with nil" do
        assert_raises(ArgumentError) { OneLogin::RubySaml::Logoutresponse.new(nil) }
      end
      it "default to empty settings" do
        assert_nil valid_logout_response_without_settings.settings
      end
      it "accept constructor-injected settings" do
        refute_nil valid_logout_response.settings
      end
      it "accept constructor-injected options" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document, nil, { :foo => :bar} )
        assert !logoutresponse.options.empty?
      end
      it "support base64 encoded responses" do
        generated_logout_response = valid_logout_response_document
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(Base64.encode64(generated_logout_response), settings)
        assert_equal generated_logout_response, logoutresponse.response
      end
    end

    describe "#validate_structure" do
        it "invalidates when the logout response has an invalid xml" do
          settings.soft = true
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(invalid_xml_logout_response_document, settings)
          assert !logoutresponse.send(:validate_structure)
          assert_includes logoutresponse.errors, "Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd"
        end

        it "raise when the logout response has an invalid xml" do
          settings.soft = false
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(invalid_xml_logout_response_document, settings)
          assert_raises OneLogin::RubySaml::ValidationError do
            logoutresponse.send(:validate_structure)
          end
        end
    end

    describe "#validate" do
      describe "when soft=true" do
        before do
          settings.soft = true
        end

        it "validate the logout response" do
          in_relation_to_request_id = random_id
          opts = { :matches_request_id => in_relation_to_request_id}

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings, opts)

          assert logoutresponse.validate

          assert_equal settings.issuer, logoutresponse.issuer
          assert_equal in_relation_to_request_id, logoutresponse.in_response_to

          assert logoutresponse.success?
          assert_empty logoutresponse.errors
        end

        it "validate the logout response extended" do
          in_relation_to_request_id = random_id
          settings.idp_entity_id = 'http://app.muda.no'
          opts = { :matches_request_id => in_relation_to_request_id}

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings, opts)
          assert logoutresponse.validate
          assert_equal in_relation_to_request_id, logoutresponse.in_response_to
          assert logoutresponse.success?
          assert_empty logoutresponse.errors
        end

        it "invalidate logout response when initiated with blank" do
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new("", settings)
          assert !logoutresponse.validate
          assert_includes logoutresponse.errors, "Blank logout response"
        end

        it "invalidate logout response when initiated with no idp cert or fingerprint" do
          settings.idp_cert_fingerprint = nil
          settings.idp_cert = nil
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document, settings)
          assert !logoutresponse.validate
          assert_includes logoutresponse.errors, "No fingerprint or certificate on settings of the logout response"
        end

        it "invalidate logout response with wrong id when given option :matches_request_id" do
          expected_request_id = "_some_other_expected_uuid"
          opts = { :matches_request_id => expected_request_id}

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document, settings, opts)

          assert !logoutresponse.validate
          refute_equal expected_request_id, logoutresponse.in_response_to
          assert_includes logoutresponse.errors, "Response does not match the request ID, expected: <#{expected_request_id}>, but was: <#{logoutresponse.in_response_to}>"
        end

        it "invalidate logout response with wrong request status" do
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, settings)

          assert !logoutresponse.success?
          assert !logoutresponse.validate
          assert_includes logoutresponse.errors, "Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <urn:oasis:names:tc:SAML:2.0:status:Requester>"
          assert_includes logoutresponse.errors, "The status code of the Logout Response was not Success, was Requester"
        end

        it "invalidate logout response when in lack of issuer setting" do
          bad_settings = settings
          bad_settings.issuer = nil
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, bad_settings)
          assert !logoutresponse.validate
          assert_includes logoutresponse.errors, "No issuer in settings of the logout response"
        end

        it "invalidate logout response with wrong issuer" do
          in_relation_to_request_id = random_id
          settings.idp_entity_id = 'http://invalid.issuer.example.com/'
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings)
          assert !logoutresponse.validate
          assert_includes logoutresponse.errors, "Doesn't match the issuer, expected: <#{logoutresponse.settings.idp_entity_id}>, but was: <http://app.muda.no>"
        end

        it "collect errors when collect_errors=true" do          
          settings.idp_entity_id = 'http://invalid.issuer.example.com/'
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, settings)
          collect_errors = true
          assert !logoutresponse.validate(collect_errors)
          assert_includes logoutresponse.errors, "Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <urn:oasis:names:tc:SAML:2.0:status:Requester>"
          assert_includes logoutresponse.errors, "Doesn't match the issuer, expected: <#{logoutresponse.settings.idp_entity_id}>, but was: <http://app.muda.no>"
        end

      end

      describe "when soft=false" do
        before do
          settings.soft = false
        end

        it "validates good logout response" do
          in_relation_to_request_id = random_id

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings)
          assert logoutresponse.validate
          assert_empty logoutresponse.errors
        end

        it "raises validation error when response initiated with blank" do
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new("", settings)

          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
          assert_includes logoutresponse.errors, "Blank logout response"
        end

        it "raises validation error when initiated with no idp cert or fingerprint" do
          settings.idp_cert_fingerprint = nil
          settings.idp_cert = nil
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document, settings)
          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
          assert_includes logoutresponse.errors, "No fingerprint or certificate on settings of the logout response"
        end

        it "raises validation error when matching for wrong request id" do

          expected_request_id = "_some_other_expected_id"
          opts = { :matches_request_id => expected_request_id}

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document, settings, opts)
          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }          
          assert_includes logoutresponse.errors, "Response does not match the request ID, expected: <#{expected_request_id}>, but was: <#{logoutresponse.in_response_to}>"
        end

        it "raise validation error for wrong request status" do
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, settings)

          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
          assert_includes logoutresponse.errors, "Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <urn:oasis:names:tc:SAML:2.0:status:Requester>"
        end

        it "raise validation error when in bad state" do
          # no settings
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, settings)
          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
          assert_includes logoutresponse.errors, "Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <urn:oasis:names:tc:SAML:2.0:status:Requester>"
        end

        it "raise validation error when in lack of issuer setting" do
          settings.issuer = nil
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, settings)
          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
          assert_includes logoutresponse.errors, "No issuer in settings of the logout response"
        end

        it "raise validation error when logout response with wrong issuer" do
          in_relation_to_request_id = random_id
          settings.idp_entity_id = 'http://invalid.issuer.example.com/'
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings)
          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
          assert_includes logoutresponse.errors, "Doesn't match the issuer, expected: <#{logoutresponse.settings.idp_entity_id}>, but was: <http://app.muda.no>"
        end
      end

      describe "#validate_signature" do
        let (:params) { OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings, random_id, "Custom Logout Message", :RelayState => 'http://example.com') }

        before do
          settings.soft = true
          settings.idp_slo_target_url = "http://example.com?field=value"
          settings.security[:logout_responses_signed] = true
          settings.security[:embed_sign] = false
          settings.certificate = ruby_saml_cert_text
          settings.private_key = ruby_saml_key_text
          settings.idp_cert = ruby_saml_cert_text
        end

        it "return true when valid RSA_SHA1 Signature" do
          settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
          params['RelayState'] = params[:RelayState]
          options = {}
          options[:get_params] = params
          logoutresponse_sign_test = OneLogin::RubySaml::Logoutresponse.new(params['SAMLResponse'], settings, options)
          assert logoutresponse_sign_test.send(:validate_signature)
        end

        it "return true when valid RSA_SHA256 Signature" do
          settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
          params['RelayState'] = params[:RelayState]
          options = {}
          options[:get_params] = params
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(params['SAMLResponse'], settings, options)
          assert logoutresponse.send(:validate_signature)
        end

        it "return false when invalid RSA_SHA1 Signature" do
          settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
          params['RelayState'] = 'http://invalid.example.com'
          options = {}
          options[:get_params] = params
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(params['SAMLResponse'], settings, options)
          assert !logoutresponse.send(:validate_signature)
        end

        it "raise when invalid RSA_SHA1 Signature" do
          settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
          settings.soft = false
          params['RelayState'] = 'http://invalid.example.com'
          options = {}
          options[:get_params] = params
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(params['SAMLResponse'], settings, options)

          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.send(:validate_signature) }
          assert logoutresponse.errors.include? "Invalid Signature on Logout Response"
        end
      end
    end
  end
end

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

    describe "#validate" do
      describe "when soft=true" do
        before do
          settings.soft = true
        end

        it "validate the response" do
          in_relation_to_request_id = random_id

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings)

          assert logoutresponse.validate

          assert_equal settings.issuer, logoutresponse.issuer
          assert_equal in_relation_to_request_id, logoutresponse.in_response_to

          assert logoutresponse.success?
        end

        it "invalidate responses with wrong id when given option :matches_uuid" do

          expected_request_id = "_some_other_expected_uuid"
          opts = { :matches_request_id => expected_request_id}

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document, settings, opts)

          assert !logoutresponse.validate
          refute_equal expected_request_id, logoutresponse.in_response_to
        end

        it "invalidate responses with wrong request status" do
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, settings)

          assert !logoutresponse.validate
          assert !logoutresponse.success?
        end
      end

      describe "when soft=false" do
        before do
          settings.soft = false
        end

        it "validates good responses" do
          in_relation_to_request_id = random_id

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings)

          assert logoutresponse.validate
        end

        it "raises validation error when matching for wrong request id" do

          expected_request_id = "_some_other_expected_id"
          opts = { :matches_request_id => expected_request_id}

          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_logout_response_document, settings, opts)

          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
        end

        it "raise validation error for wrong request status" do
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, settings)

          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
        end

        it "raise validation error when in bad state" do
          # no settings
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, settings)
          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
        end

        it "raise validation error when in lack of issuer setting" do
          bad_settings = settings
          bad_settings.issuer = nil
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_logout_response_document, bad_settings)
          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
        end

        it "raise error for invalid xml" do
          logoutresponse = OneLogin::RubySaml::Logoutresponse.new(invalid_xml_logout_response_document, settings)

          assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate }
        end
      end
    end
  end
end

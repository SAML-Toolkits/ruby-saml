require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'rexml/document'
require 'responses/logoutresponse_fixtures'

class RubySamlTest < Minitest::Test

  describe "Logoutresponse" do
    describe "#new" do
      it "raise an exception when response is initialized with nil" do
        assert_raises(ArgumentError) { OneLogin::RubySaml::Logoutresponse.new(nil) }
      end
      it "default to empty settings" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response)
        assert_nil logoutresponse.settings
      end
      it "accept constructor-injected settings" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response, settings)
        refute_nil logoutresponse.settings
      end
      it "support base64 encoded responses" do
        expected_response = valid_response
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(Base64.encode64(expected_response), settings)

        assert_equal expected_response, logoutresponse.response
      end
    end

    describe "#validate" do
      it "validate the response" do
        in_relation_to_request_id = random_id

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response({:uuid => in_relation_to_request_id}), settings)

        assert logoutresponse.validate

        assert_equal in_relation_to_request_id, logoutresponse.in_response_to

        assert logoutresponse.success?
        assert_empty logoutresponse.errors
      end

      it "validate the response extended" do
        in_relation_to_request_id = random_id
        settings.idp_entity_id = 'http://app.muda.no'

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response({:uuid => in_relation_to_request_id}), settings)

        assert logoutresponse.validate(true, in_relation_to_request_id)

        assert_equal in_relation_to_request_id, logoutresponse.in_response_to

        assert logoutresponse.success?
        assert_empty logoutresponse.errors
      end

      it "invalidate response when initiated with blank" do

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new("", settings)

        assert !logoutresponse.validate
        assert logoutresponse.errors.include? "Blank Logout Response"
      end

      it "invalidate response when initiated with no idp cert or fingerprint" do
        settings.idp_cert_fingerprint = nil
        settings.idp_cert = nil
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response, settings)
        assert !logoutresponse.validate
        assert logoutresponse.errors.include? "No fingerprint or certificate on settings"
      end

      it "invalidate responses with wrong id when given option :matches_uuid" do

        expected_request_id = "_some_other_expected_uuid"

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response, settings)

        assert !logoutresponse.validate(true, expected_request_id)
        refute_equal expected_request_id, logoutresponse.in_response_to
      end

      it "invalidate responses with wrong request status" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response, settings)

        assert !logoutresponse.validate
        assert !logoutresponse.success?
        assert logoutresponse.errors.include? "The status code of the Logout Response was not Success, was Requester"
      end

      it "invalidate responses with wrong issuer" do
        in_relation_to_request_id = random_id
        settings.idp_entity_id = 'http://invalid.issuer.example.com/'
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response({:uuid => in_relation_to_request_id}), settings)

        assert !logoutresponse.validate
        assert logoutresponse.errors.include? "Doesn't match the issuer, expected: <#{logoutresponse.settings.idp_entity_id}>, but was: <http://app.muda.no>"
      end

      it "invalidate responses when invalid logout response xml" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(invalid_xml_response, settings)

        assert !logoutresponse.is_valid?
        assert logoutresponse.errors.include? "Invalid Logout Response. Not match the saml-schema-protocol-2.0.xsd"
      end
    end

    describe "#is_valid?" do
      it "validate the response" do
        in_relation_to_request_id = random_id

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response({:uuid => in_relation_to_request_id}), settings)

        assert logoutresponse.is_valid?

        assert_equal settings.issuer, logoutresponse.issuer
        assert_equal in_relation_to_request_id, logoutresponse.in_response_to

        assert logoutresponse.success?
        assert_empty logoutresponse.errors
      end

      it "invalidate responses with wrong request status" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response, settings)

        assert !logoutresponse.is_valid?
        assert !logoutresponse.success?
        assert logoutresponse.errors.include? "The status code of the Logout Response was not Success, was Requester"
      end
    end

    describe "#validate!" do
      it "validates good responses" do
        in_relation_to_request_id = random_id

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response({:uuid => in_relation_to_request_id}), settings)

        logoutresponse.validate!
        assert_empty logoutresponse.errors
      end

      it "raises validation error when response initiated with blank" do

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new("", settings)

        assert !logoutresponse.validate
        assert_raises(OneLogin::RubySaml::ValidationError) {
          logoutresponse.validate!
        }
      end

      it "raises validation error when matching for wrong request id" do

        expected_request_id = "_some_other_expected_id"

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response, settings)

        assert_raises(OneLogin::RubySaml::ValidationError) {
          logoutresponse.validate(false, expected_request_id)
        }
      end

      it "raise validation error for wrong request status" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response, settings)

        assert_raises(OneLogin::RubySaml::ValidationError) {
          logoutresponse.validate!
        }
      end

      it "raise validation error when in bad state" do
        # no settings
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response)
        assert_raises(OneLogin::RubySaml::ValidationError) {
          logoutresponse.validate!
        }
      end

      it "raise validation error when in lack of issuer setting" do
        bad_settings = settings
        bad_settings.issuer = nil
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response, bad_settings)
        assert_raises(OneLogin::RubySaml::ValidationError) {
          logoutresponse.validate!
        }
      end

      it "raise validation error when responses with wrong issuer" do
        in_relation_to_request_id = random_id
        settings.idp_entity_id = 'http://invalid.issuer.example.com/'
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response({:uuid => in_relation_to_request_id}), settings)

        assert_raises(OneLogin::RubySaml::ValidationError) {
          logoutresponse.validate!
        }
      end

      it "raise error for invalid xml" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(invalid_xml_response, settings)

        assert_raises(OneLogin::RubySaml::ValidationError) {
          logoutresponse.validate!
        }
      end
    end
  end
end

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/logoutresponse'
require 'responses/logoutresponse_fixtures'

class RubySamlTest < Minitest::Test

  describe "Logoutresponse" do
    describe "#new" do
      it "raise an exception when response is initialized with nil" do
        assert_raises(ArgumentError) { OneLogin::RubySaml::Logoutresponse.new(nil) }
      end
      it "default to empty settings" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new( valid_response)
        assert_nil logoutresponse.settings
      end
      it "accept constructor-injected settings" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response, settings)
        refute_nil logoutresponse.settings
      end
      it "accept constructor-injected options" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response, nil, { :foo => :bar} )
        assert !logoutresponse.options.empty?
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

        assert_equal settings.issuer, logoutresponse.issuer
        assert_equal in_relation_to_request_id, logoutresponse.in_response_to

        assert logoutresponse.success?
      end

      it "invalidate responses with wrong id when given option :matches_uuid" do

        expected_request_id = "_some_other_expected_uuid"
        opts = { :matches_request_id => expected_request_id}

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response, settings, opts)

        assert !logoutresponse.validate
        refute_equal expected_request_id, logoutresponse.in_response_to
      end

      it "invalidate responses with wrong request status" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response, settings)

        assert !logoutresponse.validate
        assert !logoutresponse.success?
      end
    end

    describe "#validate!" do
      it "validates good responses" do
        in_relation_to_request_id = random_id

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response({:uuid => in_relation_to_request_id}), settings)

        logoutresponse.validate!
      end

      it "raises validation error when matching for wrong request id" do

        expected_request_id = "_some_other_expected_id"
        opts = { :matches_request_id => expected_request_id}

        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(valid_response, settings, opts)

        assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate! }
      end

      it "raise validation error for wrong request status" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response, settings)

        assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate! }
      end

      it "raise validation error when in bad state" do
        # no settings
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response)
        assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate! }
      end

      it "raise validation error when in lack of issuer setting" do
        bad_settings = settings
        bad_settings.issuer = nil
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(unsuccessful_response, bad_settings)
        assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate! }
      end

      it "raise error for invalid xml" do
        logoutresponse = OneLogin::RubySaml::Logoutresponse.new(invalid_xml_response, settings)

        assert_raises(OneLogin::RubySaml::ValidationError) { logoutresponse.validate! }
      end
    end
  end
end

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'rexml/document'
require 'responses/logoutresponse_fixtures'
class RubySamlTest < Test::Unit::TestCase

  context "Logoutresponse" do
    context "#new" do
      should "raise an exception when response is initialized with nil" do
        assert_raises(ArgumentError) { Onelogin::Saml::Logoutresponse.new(nil) }
      end
      should "default to empty settings" do
        logoutresponse = Onelogin::Saml::Logoutresponse.new( valid_response)
        assert logoutresponse.settings.nil?
      end
      should "accept constructor-injected settings" do
        logoutresponse = Onelogin::Saml::Logoutresponse.new(valid_response, settings)
        assert !logoutresponse.settings.nil?
      end
      should "accept constructor-injected options" do
        logoutresponse = Onelogin::Saml::Logoutresponse.new(valid_response, nil, { :foo => :bar} )
        assert !logoutresponse.options.empty?
      end
      should "support base64 encoded responses" do
        expected_response = valid_response
        logoutresponse = Onelogin::Saml::Logoutresponse.new(Base64.encode64(expected_response), settings)

        assert_equal expected_response, logoutresponse.response
      end
    end

    context "validation" do
      should "validate the response" do
        in_relation_to_request_id = random_id

        logoutresponse = Onelogin::Saml::Logoutresponse.new(valid_response({:uuid => in_relation_to_request_id}), settings)

        logoutresponse.validate!

        assert_equal settings.issuer, logoutresponse.issuer
        assert_equal in_relation_to_request_id, logoutresponse.in_response_to

        assert logoutresponse.success?
      end

      should "invalidate responses with wrong id when given option :matches_uuid" do

        expected_request_id = "_some_other_expected_uuid"
        opts = { :matches_request_id => expected_request_id}

        logoutresponse = Onelogin::Saml::Logoutresponse.new(valid_response, settings, opts)

        assert !logoutresponse.validate
        assert_not_equal expected_request_id, logoutresponse.in_response_to
      end

      should "invalidate responses with wrong request status" do
        logoutresponse = Onelogin::Saml::Logoutresponse.new(invalid_response, settings)

        logoutresponse.validate!

        assert !logoutresponse.success?
      end
    end

  end

  # logoutresponse fixtures
  def random_id
    "_#{UUID.new.generate}"
  end

end

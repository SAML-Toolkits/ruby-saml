require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'responses/logoutresponse_fixtures'

class RubySamlTest < Test::Unit::TestCase

  context "SloLogoutrequest" do
    should "raise an exception when response is initialized with nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::SloLogoutrequest.new(nil) }
    end

    context "#is_valid?" do
      should "return false when response is initialized with blank data" do
        request = OneLogin::RubySaml::SloLogoutrequest.new('')
        assert !request.is_valid?
      end

      should "return true when the request is initialized with valid data" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert request.is_valid?
        assert_equal 'someone@example.org', request.name_id
      end

      should "should be idempotent when the response is initialized with invalid data" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_xml_response)
        assert !request.is_valid?
        assert !request.is_valid?
      end

      should "should be idempotent when the response is initialized with valid data" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert request.is_valid?
        assert request.is_valid?
      end

      should "raise error for invalid xml" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_xml_response)
        assert_raises(OneLogin::RubySaml::ValidationError) { logout_request.validate! }
      end
    end

    context "#name_id" do
      should "extract the value of the name id element" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "someone@example.org", request.name_id
      end
    end

    context "#issuer" do
      should "return the issuer inside the request" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "https://app.onelogin.com/saml/metadata/SOMEACCOUNT", request.issuer
      end
    end

    context "#id" do
      should "extract the value of the ID attribute" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "_c0348950-935b-0131-1060-782bcb56fcaa", request.id
      end
    end

  end
end

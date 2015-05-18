require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'logout_responses/logoutresponse_fixtures'

require 'onelogin/ruby-saml/slo_logoutrequest'

class RubySamlTest < Minitest::Test

  describe "SloLogoutrequest" do
    it "raise an exception when the logout request is initialized with nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::SloLogoutrequest.new(nil) }
    end

    describe "#is_valid?" do
      it "return false when the logout request is initialized with blank data" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new('')
        assert !logout_request.is_valid?
      end

      it "return true when the logout_request is initialized with valid data" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert logout_request.is_valid?
        assert_equal 'someone@example.org', logout_request.name_id
      end

      it "should be idempotent when the logout_request is initialized with invalid data" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_xml_logout_response_document)
        assert !logout_request.is_valid?
        assert !logout_request.is_valid?
      end

      it "should be idempotent when the response is initialized with valid data" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert logout_request.is_valid?
        assert logout_request.is_valid?
      end

      it "return false for invalid xml" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_xml_logout_response_document)
        assert !logout_request.is_valid?
      end
    end

    describe "#name_id" do
      it "extract the value of the name id element" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "someone@example.org", logout_request.name_id
      end
    end

    describe "#issuer" do
      it "return the issuer inside the logout request" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "https://app.onelogin.com/saml/metadata/SOMEACCOUNT", logout_request.issuer
      end
    end

    describe "#id" do
      it "extract the value of the ID attribute" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "_c0348950-935b-0131-1060-782bcb56fcaa", logout_request.id
      end
    end
  end
end

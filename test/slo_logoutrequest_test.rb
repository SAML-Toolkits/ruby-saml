require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'responses/logoutresponse_fixtures'

class RubySamlTest < Minitest::Test

  describe "SloLogoutrequest" do
    it "raise an exception when response is initialized with nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::SloLogoutrequest.new(nil) }
    end

    describe "#is_valid?" do
      it "return false when response is initialized with blank data" do
        request = OneLogin::RubySaml::SloLogoutrequest.new('')
        assert !request.is_valid?
      end

      it "return true when the request is initialized with valid data" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert request.is_valid?
        assert_equal 'someone@example.org', request.name_id
      end

      it "should be idempotent when the response is initialized with invalid data" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_xml_response)
        assert !request.is_valid?
        assert !request.is_valid?
      end

      it "should be idempotent when the response is initialized with valid data" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert request.is_valid?
        assert request.is_valid?
      end

      it "raise error for invalid xml" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_xml_response)
        assert_raises(OneLogin::RubySaml::ValidationError) { logout_request.validate! }
      end
    end

    describe "#name_id" do
      it "extract the value of the name id element" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "someone@example.org", request.name_id
      end
    end

    describe "#issuer" do
      it "return the issuer inside the request" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "https://app.onelogin.com/saml/metadata/SOMEACCOUNT", request.issuer
      end
    end

    describe "#id" do
      it "extract the value of the ID attribute" do
        request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
        assert_equal "_c0348950-935b-0131-1060-782bcb56fcaa", request.id
      end
    end
  end
end

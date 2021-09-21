require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require File.expand_path(File.join(File.dirname(__FILE__), "requests/logoutrequest_fixtures"))

class SloLogoutrequestTest < Minitest::Test

  describe "SloLogoutrequest" do

    describe "#new" do
      it "raise an exception when request is initialized with nil" do
        assert_raises(ArgumentError) { OneLogin::RubySaml::SloLogoutrequest.new(nil) }
      end
      it "default to empty settings" do
        logoutrequest = OneLogin::RubySaml::SloLogoutrequest.new(valid_request)
        assert logoutrequest.settings.nil?
      end
      it "accept constructor-injected settings" do
        logoutrequest = OneLogin::RubySaml::SloLogoutrequest.new(valid_request, settings)
        assert !logoutrequest.settings.nil?
      end
      it "accept constructor-injected options" do
        logoutrequest = OneLogin::RubySaml::SloLogoutrequest.new(valid_request, nil, { :foo => :bar} )
        assert !logoutrequest.options.empty?
      end
      it "support base64 encoded requests" do
        expected_request = valid_request
        logoutrequest = OneLogin::RubySaml::SloLogoutrequest.new(Base64.encode64(expected_request), settings)

        assert_equal expected_request, logoutrequest.request
      end
    end

    describe "#validate" do
      it "validate the request" do
        in_relation_to_request_id = random_id
        settings.idp_entity_id = "https://example.com/idp"
        logoutrequest = OneLogin::RubySaml::SloLogoutrequest.new(valid_request({:uuid => in_relation_to_request_id}), settings)

        assert logoutrequest.validate

        assert_equal settings.idp_entity_id, logoutrequest.issuer

        assert_equal "testuser@example.com", logoutrequest.nameid

        assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", logoutrequest.nameid_format
      end

    end

    describe "#validate!" do
      it "validates good requests" do
        in_relation_to_request_id = random_id

        logoutrequest = OneLogin::RubySaml::SloLogoutrequest.new(valid_request({:uuid => in_relation_to_request_id}), settings)

        logoutrequest.validate!
      end

      it "raise error for invalid xml" do
        logoutrequest = OneLogin::RubySaml::SloLogoutrequest.new(invalid_xml_request, settings)

        assert_raises(OneLogin::RubySaml::ValidationError) { logoutrequest.validate! }
      end
    end

    describe "#request_id" do
      it "extract the value of the Response ID" do
        logoutrequest = OneLogin::RubySaml::SloLogoutrequest.new(valid_request, settings)
        assert_equal "_28024690-000e-0130-b6d2-38f6b112be8b", logoutrequest.request_id
      end
    end

  end
end

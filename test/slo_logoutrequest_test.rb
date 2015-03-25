require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/slo_logoutrequest'

class RubySamlTest < Minitest::Test

  describe "SloLogoutrequest" do
    it "raise an exception when logout request is initialized with nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::SloLogoutrequest.new(nil) }
    end
  end

  describe "#is_valid?" do
    it "return false when logout request is initialized with blank data" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new('')
      assert !logout_request.is_valid?
      assert logout_request.errors.include? 'Blank Logout Request'      
    end

    it "return true when the logout request is initialized with valid data" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = 'https://app.onelogin.com/saml/metadata/SOMEACCOUNT'
      logout_request.settings = settings

      assert logout_request.is_valid?
      assert_empty logout_request.errors
      assert_equal 'someone@example.org', logout_request.name_id      
    end

    it "should be idempotent when the logout request is initialized with invalid data" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_logout_request_document)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = 'https://app.onelogin.com/saml/metadata/SOMEACCOUNT'
      logout_request.settings = settings

      assert !logout_request.is_valid?
      assert_equal ['Invalid Logout Request. Not match the saml-schema-protocol-2.0.xsd'], logout_request.errors
      assert !logout_request.is_valid?
      assert_equal ['Invalid Logout Request. Not match the saml-schema-protocol-2.0.xsd'], logout_request.errors
    end

    it "should be idempotent when the logout request is initialized with valid data" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = 'https://app.onelogin.com/saml/metadata/SOMEACCOUNT'
      logout_request.settings = settings

      assert logout_request.is_valid?
      assert_empty logout_request.errors
      assert logout_request.is_valid?
      assert_empty logout_request.errors
    end

    it "raise error for invalid xml" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_logout_request_document)
      assert_raises(OneLogin::RubySaml::ValidationError) { logout_request.validate! }      
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

  describe "#not_on_or_after" do
    it "extract the value of the NotOnOrAfter attribute" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      time_value = '2014-07-17T01:01:48Z'
      assert_equal nil, logout_request.not_on_or_after
      logout_request.document.root.attributes['NotOnOrAfter'] = time_value
      assert_equal Time.parse(time_value), logout_request.not_on_or_after
    end
  end

  describe "#current_url" do
    it "return the value of the current_url" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      settings = OneLogin::RubySaml::Settings.new
      slo_url = 'http://sp.example.com/slo'
      settings.single_logout_service_url = slo_url
      logout_request.settings = settings
      assert_equal slo_url, logout_request.send(:current_url)
    end
  end

  describe '#session_indexes' do
    it "return empty array when no SessionIndex" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      assert_equal [], logout_request.session_indexes
    end

    it "return an Array with one SessionIndex" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_xml_with_session_index)
      assert_equal ['_ea853497-c58a-408a-bc23-c849752d9741'], logout_request.session_indexes
    end
  end

  describe "#validate_id" do
    it "return true when there is a valid ID in the logout request" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      assert logout_request.send(:validate_id)
      assert_empty logout_request.errors
    end

    it "return false when there is an invalid ID in the logout request" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new('')
        assert !logout_request.send(:validate_id)
        assert logout_request.errors.include? "Missing ID attribute on Logout Request"
    end
  end

  describe "#validate_version" do
    it "return true when the logout request is SAML 2.0 Version" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      assert logout_request.send(:validate_version)
    end

    it "return false when the logout request is not SAML 2.0 Version" do
        logout_request = OneLogin::RubySaml::SloLogoutrequest.new('')
        assert !logout_request.send(:validate_version)
        assert logout_request.errors.include? "Unsupported SAML version"
    end
  end

  describe "#validate_not_on_or_after" do
    it "return true when the logout request has a valid NotOnOrAfter or does not contain any" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      assert logout_request.send(:validate_not_on_or_after)
      assert_empty logout_request.errors

      time     = Time.parse("2011-06-14T18:25:01.516Z")
      Time.stubs(:now).returns(time)
      time_value = '2014-07-17T01:01:48Z'
      logout_request.document.root.attributes['NotOnOrAfter'] = time_value
      assert logout_request.send(:validate_not_on_or_after)
      assert_empty logout_request.errors
    end

    it "return false when the logout request has an invalid NotOnOrAfter" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      logout_request.document.root.attributes['NotOnOrAfter'] = '2014-07-17T01:01:48Z'
      assert !logout_request.send(:validate_not_on_or_after, true)
      assert /Current time is on or after NotOnOrAfter/.match(logout_request.errors[0])
    end

    it "raise when the logout request has an invalid NotOnOrAfter" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      logout_request.document.root.attributes['NotOnOrAfter'] = '2014-07-17T01:01:48Z'
      assert_raises(OneLogin::RubySaml::ValidationError, "Current time is on or after NotOnOrAfter") do
        logout_request.send(:validate_not_on_or_after, false)
      end
    end
  end

  describe "#validate_request_state" do
    it "return true when valid logout request xml" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      assert logout_request.send(:validate_request_state, true)
      assert_empty logout_request.errors
      assert logout_request.send(:validate_request_state, false)
      assert_empty logout_request.errors
    end

    it "return false when invalid logout request xml" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new('')
      assert !logout_request.send(:validate_request_state, true)
      assert logout_request.errors.include? "Blank Logout Request"
    end

    it "raise error for invalid xml" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new('')
      assert_raises(OneLogin::RubySaml::ValidationError, "Blank Logout Request") do
        logout_request.send(:validate_request_state, false)
      end
    end
  end

  describe "#validate_structure" do
    it "return true when encountering a valid Logout Request xml" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      assert logout_request.send(:validate_structure)
      assert_empty logout_request.errors
    end

    it "return false when encountering a Logout Request bad formatted" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_logout_request_document)
      assert !logout_request.send(:validate_structure, true)
      assert logout_request.errors.include? "Invalid Logout Request. Not match the saml-schema-protocol-2.0.xsd"
    end

    it "raise when encountering a Logout Request bad formatted" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_logout_request_document)
      assert_raises(OneLogin::RubySaml::ValidationError, "Element '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer': This element is not expected") do
        logout_request.send(:validate_structure, false)
      end
    end
  end

  describe "#validate_destination" do
    it "return true when the destination of the Logout Request matchs the service logout url or there is not Destination attribute" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      settings = OneLogin::RubySaml::Settings.new
      logout_request.settings = settings
      assert logout_request.send(:validate_destination)
      assert_empty logout_request.errors

      logout_request.settings.single_logout_service_url = 'http://sp.example.com/sls'
      logout_request.document.root.attributes['Destination'] = 'http://sp.example.com/sls'
      assert logout_request.send(:validate_destination)
      assert_empty logout_request.errors
    end

    it "return false when the destination of the Logout Request does not match the service logout url" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      logout_request.document.root.attributes['Destination'] = 'http://sp.example.com/sls'
      settings = OneLogin::RubySaml::Settings.new
      settings.single_logout_service_url = 'invalid_sls'
      logout_request.settings = settings
      assert !logout_request.send(:validate_destination, true)
      assert logout_request.errors.include? "The Logout Request was received at #{logout_request.destination} instead of #{logout_request.settings.single_logout_service_url}"
    end

    it "raise when the destination of the Logout Request does not match the service logout url" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      logout_request.document.root.attributes['Destination'] = 'http://sp.example.com/sls'
      settings = OneLogin::RubySaml::Settings.new
      settings.single_logout_service_url = 'invalid_sls'
      logout_request.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError, "The Logout Request was received at #{logout_request.destination} instead of #{logout_request.settings.single_logout_service_url}") do
        logout_request.send(:validate_destination, false)
      end
    end
  end

  describe "#validate_issuer" do
    it "return true when the issuer of the Logout Request matchs the IdP entityId" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = 'https://app.onelogin.com/saml/metadata/SOMEACCOUNT'
      logout_request.settings = settings
      assert logout_request.send(:validate_issuer)
    end

    it "return false when the issuer of the Logout Request does not match the IdP entityId" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = 'http://idp.example.com/invalid'
      logout_request.settings = settings
      assert !logout_request.send(:validate_issuer, true)
      assert logout_request.errors.include? "Doesn't match the issuer, expected: <#{logout_request.settings.idp_entity_id}>, but was: <https://app.onelogin.com/saml/metadata/SOMEACCOUNT>"
    end

    it "raise when the issuer of the Logout Request does not match the IdP entityId" do
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = 'http://idp.example.com/invalid'
      logout_request.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError, "Doesn't match the issuer, expected: <#{logout_request.settings.idp_entity_id}>, but was: <https://app.onelogin.com/saml/metadata/SOMEACCOUNT>") do
        logout_request.send(:validate_issuer, false)
      end
    end
  end
end

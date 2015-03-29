require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/slo_logoutrequest'
require 'onelogin/ruby-saml/logoutrequest'
require 'timecop'

class RubySamlTest < Minitest::Test

  describe "SloLogoutrequest" do
    let(:settings) { OneLogin::RubySaml::Settings.new }
    let(:logout_request) { OneLogin::RubySaml::SloLogoutrequest.new(logout_request_document) }

    before do
      settings.idp_entity_id = 'https://app.onelogin.com/saml/metadata/SOMEACCOUNT'
      logout_request.settings = settings
    end

    describe "initiator" do
      it "raise an exception when logout request is initialized with nil" do
        assert_raises(ArgumentError) { OneLogin::RubySaml::SloLogoutrequest.new(nil) }
      end
    end

    describe "#is_valid?" do
      it "return false when logout request is initialized with blank data" do
        logout_request_blank = OneLogin::RubySaml::SloLogoutrequest.new('')
        assert !logout_request_blank.is_valid?
        assert logout_request_blank.errors.include? 'Blank Logout Request'      
      end

      it "return true when the logout request is initialized with valid data" do
        assert logout_request.is_valid?
        assert_empty logout_request.errors
        assert_equal 'someone@example.org', logout_request.name_id      
      end

      it "should be idempotent when the logout request is initialized with invalid data" do
        invalid_logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_logout_request_document)
        invalid_logout_request.settings = settings

        assert !invalid_logout_request.is_valid?
        assert_equal ['Invalid Logout Request. Not match the saml-schema-protocol-2.0.xsd'], invalid_logout_request.errors
        assert !invalid_logout_request.is_valid?
        assert_equal ['Invalid Logout Request. Not match the saml-schema-protocol-2.0.xsd'], invalid_logout_request.errors
      end

      it "should be idempotent when the logout request is initialized with valid data" do
        assert logout_request.is_valid?
        assert_empty logout_request.errors
        assert logout_request.is_valid?
        assert_empty logout_request.errors
      end

      it "raise error for invalid xml" do
        invalid_logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_logout_request_document)
        assert_raises(OneLogin::RubySaml::ValidationError) { invalid_logout_request.validate! }      
      end
    end

    describe "#name_id" do
      it "extract the value of the name id element" do
        assert_equal "someone@example.org", logout_request.name_id
      end
    end

    describe "#issuer" do
      it "return the issuer inside the logout request" do
        assert_equal "https://app.onelogin.com/saml/metadata/SOMEACCOUNT", logout_request.issuer
      end
    end

    describe "#id" do
      it "extract the value of the ID attribute" do
        assert_equal "_c0348950-935b-0131-1060-782bcb56fcaa", logout_request.id
      end
    end

    describe "#not_on_or_after" do
      it "extract the value of the NotOnOrAfter attribute" do
        time_value = '2014-07-17T01:01:48Z'
        assert_equal nil, logout_request.not_on_or_after
        logout_request.document.root.attributes['NotOnOrAfter'] = time_value
        assert_equal Time.parse(time_value), logout_request.not_on_or_after
      end
    end

    describe "#current_url" do
      it "return the value of the current_url" do
        slo_url = 'http://sp.example.com/slo'
        settings.single_logout_service_url = slo_url
        logout_request.settings = settings
        assert_equal slo_url, logout_request.send(:current_url)
      end
    end

    describe '#session_indexes' do
      it "return empty array when no SessionIndex" do
        assert_equal [], logout_request.session_indexes
      end

      it "return an Array with one SessionIndex" do
        logout_request_with_session_index = OneLogin::RubySaml::SloLogoutrequest.new(logout_request_xml_with_session_index)
        assert_equal ['_ea853497-c58a-408a-bc23-c849752d9741'], logout_request_with_session_index.session_indexes
      end
    end

    describe "#validate_id" do
      it "return true when there is a valid ID in the logout request" do
        assert logout_request.send(:validate_id)
        assert_empty logout_request.errors
      end

      it "return false when there is an invalid ID in the logout request" do
          logout_request_blank = OneLogin::RubySaml::SloLogoutrequest.new('')
          assert !logout_request_blank.send(:validate_id)
          assert logout_request_blank.errors.include? "Missing ID attribute on Logout Request"
      end
    end

    describe "#validate_version" do
      it "return true when the logout request is SAML 2.0 Version" do
        assert logout_request.send(:validate_version)
      end

      it "return false when the logout request is not SAML 2.0 Version" do
          logout_request_blank = OneLogin::RubySaml::SloLogoutrequest.new('')
          assert !logout_request_blank.send(:validate_version)
          assert logout_request_blank.errors.include? "Unsupported SAML version"
      end
    end

    describe "#validate_not_on_or_after" do
      it "return true when the logout request has a valid NotOnOrAfter or does not contain any" do
        assert logout_request.send(:validate_not_on_or_after)
        assert_empty logout_request.errors

        Timecop.freeze Time.parse('2011-06-14T18:25:01.516Z') do
          time_value = '2014-07-17T01:01:48Z'
          logout_request.document.root.attributes['NotOnOrAfter'] = time_value
          assert logout_request.send(:validate_not_on_or_after)
          assert_empty logout_request.errors
        end
      end

      it "return false when the logout request has an invalid NotOnOrAfter" do
        logout_request.document.root.attributes['NotOnOrAfter'] = '2014-07-17T01:01:48Z'
        assert !logout_request.send(:validate_not_on_or_after, true)
        assert /Current time is on or after NotOnOrAfter/.match(logout_request.errors[0])
      end

      it "raise when the logout request has an invalid NotOnOrAfter" do
        logout_request.document.root.attributes['NotOnOrAfter'] = '2014-07-17T01:01:48Z'
        assert_raises(OneLogin::RubySaml::ValidationError, "Current time is on or after NotOnOrAfter") do
          logout_request.send(:validate_not_on_or_after, false)
        end
      end
    end

    describe "#validate_request_state" do
      it "return true when valid logout request xml" do
        assert logout_request.send(:validate_request_state, true)
        assert_empty logout_request.errors
        assert logout_request.send(:validate_request_state, false)
        assert_empty logout_request.errors
      end

      it "return false when invalid logout request xml" do
        logout_request_blank = OneLogin::RubySaml::SloLogoutrequest.new('')
        assert !logout_request_blank.send(:validate_request_state, true)
        assert logout_request_blank.errors.include? "Blank Logout Request"
      end

      it "raise error for invalid xml" do
        logout_request_blank = OneLogin::RubySaml::SloLogoutrequest.new('')
        assert_raises(OneLogin::RubySaml::ValidationError, "Blank Logout Request") do
          logout_request_blank.send(:validate_request_state, false)
        end
      end
    end

    describe "#validate_structure" do
      it "return true when encountering a valid Logout Request xml" do
        assert logout_request.send(:validate_structure)
        assert_empty logout_request.errors
      end

      it "return false when encountering a Logout Request bad formatted" do
        invalid_logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_logout_request_document)
        assert !invalid_logout_request.send(:validate_structure, true)
        assert invalid_logout_request.errors.include? "Invalid Logout Request. Not match the saml-schema-protocol-2.0.xsd"
      end

      it "raise when encountering a Logout Request bad formatted" do
        invalid_logout_request = OneLogin::RubySaml::SloLogoutrequest.new(invalid_logout_request_document)
        assert_raises(OneLogin::RubySaml::ValidationError, "Element '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer': This element is not expected") do
          invalid_logout_request.send(:validate_structure, false)
        end
      end
    end

    describe "#validate_destination" do
      it "return true when the destination of the Logout Request matchs the service logout url or there is not Destination attribute" do
        assert logout_request.send(:validate_destination)
        assert_empty logout_request.errors

        logout_request.settings.single_logout_service_url = 'http://sp.example.com/sls'
        logout_request.document.root.attributes['Destination'] = 'http://sp.example.com/sls'
        assert logout_request.send(:validate_destination)
        assert_empty logout_request.errors
      end

      it "return false when the destination of the Logout Request does not match the service logout url" do
        logout_request.document.root.attributes['Destination'] = 'http://sp.example.com/sls'
        logout_request.settings.single_logout_service_url = 'invalid_sls'
        assert !logout_request.send(:validate_destination, true)
        assert logout_request.errors.include? "The Logout Request was received at #{logout_request.destination} instead of #{logout_request.settings.single_logout_service_url}"
      end

      it "raise when the destination of the Logout Request does not match the service logout url" do
        logout_request.document.root.attributes['Destination'] = 'http://sp.example.com/sls'
        logout_request.settings.single_logout_service_url = 'invalid_sls'
        assert_raises(OneLogin::RubySaml::ValidationError, "The Logout Request was received at #{logout_request.destination} instead of #{logout_request.settings.single_logout_service_url}") do
          logout_request.send(:validate_destination, false)
        end
      end
    end

    describe "#validate_issuer" do
      it "return true when the issuer of the Logout Request matchs the IdP entityId" do
        logout_request.settings.idp_entity_id = 'https://app.onelogin.com/saml/metadata/SOMEACCOUNT'
        assert logout_request.send(:validate_issuer)
      end

      it "return false when the issuer of the Logout Request does not match the IdP entityId" do
        logout_request.settings.idp_entity_id = 'http://idp.example.com/invalid'
        assert !logout_request.send(:validate_issuer, true)
        assert logout_request.errors.include? "Doesn't match the issuer, expected: <#{logout_request.settings.idp_entity_id}>, but was: <https://app.onelogin.com/saml/metadata/SOMEACCOUNT>"
      end

      it "raise when the issuer of the Logout Request does not match the IdP entityId" do
        logout_request.settings.idp_entity_id = 'http://idp.example.com/invalid'
        assert_raises(OneLogin::RubySaml::ValidationError, "Doesn't match the issuer, expected: <#{logout_request.settings.idp_entity_id}>, but was: <https://app.onelogin.com/saml/metadata/SOMEACCOUNT>") do
          logout_request.send(:validate_issuer, false)
        end
      end
    end

    describe "#validate_signature" do
      before do
        settings.idp_slo_target_url = "http://example.com?field=value"
        settings.security[:logout_requests_signed] = true
        settings.security[:embed_sign] = false        
        settings.certificate = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text
        settings.idp_cert = ruby_saml_cert_text
      end

      it "return true when valid RSA_SHA1 Signature" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        params = OneLogin::RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')
        params['RelayState'] = params[:RelayState]
        logout_request_sign_test = OneLogin::RubySaml::SloLogoutrequest.new(params['SAMLRequest'])
        logout_request_sign_test.settings = settings
        assert logout_request_sign_test.send(:validate_signature, true, params)
      end

      it "return true when valid RSA_SHA256 Signature" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        params = OneLogin::RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')
        logout_request_sign_test = OneLogin::RubySaml::SloLogoutrequest.new(params['SAMLRequest'])
        params['RelayState'] = params[:RelayState]
        logout_request_sign_test.settings = settings
        assert logout_request_sign_test.send(:validate_signature, true, params)
      end

      it "return false when invalid RSA_SHA1 Signature" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        params = OneLogin::RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')
        logout_request_sign_test = OneLogin::RubySaml::SloLogoutrequest.new(params['SAMLRequest'])
        logout_request_sign_test.settings = settings
        params['RelayState'] = 'http://invalid.exampcle.com'
        logout_request_sign_test.send(:validate_signature, true, params)
        assert !logout_request_sign_test.send(:validate_signature, true, params)
      end

      it "raise when invalid RSA_SHA1 Signature" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        params = OneLogin::RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')
        logout_request_sign_test = OneLogin::RubySaml::SloLogoutrequest.new(params['SAMLRequest'])
        logout_request_sign_test.settings = settings
        params['RelayState'] = 'http://invalid.example.com'
        assert_raises(OneLogin::RubySaml::ValidationError, "Invalid Signature on Logout Request") do
          assert logout_request_sign_test.send(:validate_signature, false, params)
        end
      end
    end
  end
end

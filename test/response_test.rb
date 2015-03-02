require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RubySamlTest < Minitest::Test

  describe "Response" do
    it "raise an exception when response is initialized with nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::Response.new(nil) }
    end

    it "be able to parse a document which contains ampersands" do
      XMLSecurity::SignedDocument.any_instance.stubs(:digests_match?).returns(true)
      OneLogin::RubySaml::Response.any_instance.stubs(:validate_conditions).returns(true)

      response = OneLogin::RubySaml::Response.new(ampersands_response)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = 'c51985d947f1be57082025050846eb27f6cab783'
      response.settings = settings
      assert !response.validate!
    end

    it "adapt namespace" do
      response = OneLogin::RubySaml::Response.new(response_document)
      refute_nil response.name_id
      response = OneLogin::RubySaml::Response.new(response_document_2)
      refute_nil response.name_id
      response = OneLogin::RubySaml::Response.new(response_document_3)
      refute_nil response.name_id
    end

    it "default to raw input when a response is not Base64 encoded" do
      decoded  = Base64.decode64(response_document_2)
      response = OneLogin::RubySaml::Response.new(decoded)
      assert response.document
    end
  end

  describe "Assertion" do
    it "only retreive an assertion with an ID that matches the signature's reference URI" do
      response = OneLogin::RubySaml::Response.new(wrapped_response_2)
      response.stubs(:conditions).returns(nil)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = signature_fingerprint_1
      response.settings = settings
      assert_nil response.name_id
      response.send(:validate_structure)
      assert response.errors.include? "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd"
    end
  end

  describe "#validate" do
    it "raise when no settings asigned to the response" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert_raises(OneLogin::RubySaml::ValidationError, "No settings on SAML Response") do
        response.validate!
      end
    end

    it "raise when response is initialized with blank data" do
      response = OneLogin::RubySaml::Response.new('')
      assert_raises(OneLogin::RubySaml::ValidationError, "Blank SAML Response") do
        response.validate!
      end
    end

    it "raise when No fingerprint or certificate on settings" do
      response = OneLogin::RubySaml::Response.new(response_document)
      settings2 = OneLogin::RubySaml::Settings.new
      settings2.idp_cert_fingerprint = nil
      settings2.idp_cert = nil
      response.settings = settings2
      assert_raises(OneLogin::RubySaml::ValidationError, "No fingerprint or certificate on settings") do
        response.validate!
      end
    end

    it "raise when the status is not 'Success', and shows the StatusMessage" do
      response = OneLogin::RubySaml::Response.new(response_statuscode_responder_and_msg)
      response.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError, "The status code of the Response was not Success, was Responder -> something_is_wrong") do
        response.validate!
      end
    end

    it "raise when encountering a condition that prevents the document from being valid" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError, "Current time is on or after NotOnOrAfter condition") do
        response.validate!
      end
    end

    it "raise when encountering a SAML Response with bad formatted" do
      response = OneLogin::RubySaml::Response.new(response_document_2)
      response.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError){ response.validate! }
    end
  end

  describe "#validate!" do
    it "raise when encountering a condition that prevents the document from being valid" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert_raises(OneLogin::RubySaml::ValidationError) do
        response.validate!
      end
    end

    it "raise when the inResponseTo value does not match the Request ID" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError, "The InResponseTo of the Response: _fc4a34b0-7efb-012e-caae-782bcb13bb38, does not match the ID of the AuthNRequest sent by the SP: invalid_request_id") do
        response.validate!(false, 'invalid_request_id')
      end
    end

    it "raise when the assertion contains encrypted attributes" do
      response = OneLogin::RubySaml::Response.new(response_encrypted_attrs)
      response.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError, "There is an EncryptedAttribute in the Response and this SP not support them") do
        response.validate!
      end
    end

    it "raise when there is no valid audience" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      response.settings.issuer = 'invalid'
      assert_raises(OneLogin::RubySaml::ValidationError, "#{response.settings.issuer} is not a valid audience for this Response") do
        response.validate!
      end
    end

    it "raise when the destination od the SAML Response does not match the assertion consumer service url" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      response.settings.assertion_consumer_service_url = 'invalid_acs'
      assert_raises(OneLogin::RubySaml::ValidationError, "The response was received at #{response.destination} instead of #{response.settings.assertion_consumer_service_url}") do
        response.validate!
      end
    end

    it "raise when  the issuer of the Message does not match the IdP entityId" do
      response = OneLogin::RubySaml::Response.new(response_invalid_issuer_message)
      response.settings = settings
      response.settings.idp_entity_id = 'http://idp.example.com/'
      assert_raises(OneLogin::RubySaml::ValidationError, "Doesn't match the issuer, expected: <#{response.settings.idp_entity_id}>, but was: <http://invalid.issuer.example.com/>") do
        response.send(:validate_issuer, false)
      end
    end

    it "raise when the issuer of the Assertion does not match the IdP entityId" do
      response = OneLogin::RubySaml::Response.new(response_invalid_issuer_assertion)
      response.settings = settings
      response.settings.idp_entity_id = 'http://idp.example.com/'
      assert_raises(OneLogin::RubySaml::ValidationError, "Doesn't match the issuer, expected: <#{response.settings.idp_entity_id}>, but was: <http://invalid.issuer.example.com/>") do
        response.send(:validate_issuer, false)
      end
    end

    it "raise when the session has expired" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError, "The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response") do
        response.send(:validate_session_expiration, false)
      end
    end

    it "raise when no subject confirmation data" do
      response = OneLogin::RubySaml::Response.new(response_no_subjectconfirmation_data)
      response.settings = settings
      assert_raises(OneLogin::RubySaml::ValidationError, "A valid SubjectConfirmation was not found on this Response") do
        response.send(:validate_subject_confirmation, false)
      end
    end
  end

  describe "#validate_response_state" do
    it "return false when no settings asigned to the response" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert !response.send(:validate_response_state, true)
      assert response.errors.include? "No settings on SAML Response"
    end

    it "return false when response is initialized with blank data" do
      response = OneLogin::RubySaml::Response.new('')
      assert !response.send(:validate_response_state, true)
      assert response.errors.include? "Blank SAML Response"
    end

    it "return false when No fingerprint or certificate on settings" do
      response = OneLogin::RubySaml::Response.new(response_document)
      settings_wrong = OneLogin::RubySaml::Settings.new
      settings_wrong.idp_cert_fingerprint = nil
      settings_wrong.idp_cert = nil
      response.settings = settings_wrong
      assert !response.send(:validate_response_state, true)
      assert response.errors.include? "No fingerprint or certificate on settings"
    end

    it "return true when correct settings asigned to the response" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      assert response.send(:validate_response_state, true)
      assert_empty response.errors
    end
  end


  describe "#validate_structure" do
    it "return false when encountering a SAML Response bad formatted" do
      response = OneLogin::RubySaml::Response.new(response_document_2)
      assert !response.send(:validate_structure, true)
      assert response.errors.include? "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd"
    end

    it "raise when encountering a SAML Response bad formatted" do
      response = OneLogin::RubySaml::Response.new(response_document_2)
      assert_raises(OneLogin::RubySaml::ValidationError, "Element '{http://www.w3.org/2000/09/xmldsig#}DigestValue': 'Digest Stuff' is not a valid value of the atomic type '{http://www.w3.org/2000/09/xmldsig#}DigestValueType'") do
        response.send(:validate_structure, false)
      end
    end
  end

  describe "#valid_saml?" do
    it "return false when encountering a SAML Response bad formatted" do
      response = OneLogin::RubySaml::Response.new(response_document_2)
      assert !response.send(:valid_saml?, response.document, true)
    end

    it "return false when encountering a SAML Response bad formatted" do
      response = OneLogin::RubySaml::Response.new(response_document_2)
      assert_raises(OneLogin::RubySaml::ValidationError, "Element '{http://www.w3.org/2000/09/xmldsig#}DigestValue': 'Digest Stuff' is not a valid value of the atomic type '{http://www.w3.org/2000/09/xmldsig#}DigestValueType'") do
        response.send(:valid_saml?, response.document, false)
      end
    end
  end

  describe "#validate_id" do
    it "return false when no ID present in the SAML Response" do
      response = OneLogin::RubySaml::Response.new(response_no_id)
      assert !response.send(:validate_id)
      assert response.errors.include? "Missing ID attribute on SAML Response"
    end
  end

  describe "#validate_version" do
    it "return false when no 2.0 Version present in the SAML Response" do
      response = OneLogin::RubySaml::Response.new(response_no_version)
      assert !response.send(:validate_version)
      assert response.errors.include? "Unsupported SAML version"
    end
  end

  describe "#validate_num_assertion" do
    it "return false when no 2.0 Version present in the SAML Response" do
      response = OneLogin::RubySaml::Response.new(response_multi_assertion)
      assert !response.send(:validate_num_assertion)
      assert response.errors.include? "SAML Response must contain 1 assertion"
    end

    it "return false when no Assertion found" do
      resp_xml = Base64.decode64(response_document_4).gsub(/emailAddress/,'test')
      response = OneLogin::RubySaml::Response.new(Base64.encode64(resp_xml))
      response.stubs(:conditions).returns(nil)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = signature_fingerprint_1
      response.settings = settings
      assert !response.send(:validate_num_assertion)
      assert response.errors.include? "SAML Response must contain 1 assertion"
    end
  end

  describe "validate_success_status" do
    it "return false when the status if no Status provided" do
      response = OneLogin::RubySaml::Response.new(response_no_status)
      assert !response.send(:validate_success_status, true)
      assert response.errors.include? "The status code of the Response was not Success"
    end

    it "return false when the status if no StatusCode provided" do
      response = OneLogin::RubySaml::Response.new(response_no_statuscode)
      assert !response.send(:validate_success_status, true)
      assert response.errors.include? "The status code of the Response was not Success"
    end

    it "return false when the status is not 'Success'" do
      response = OneLogin::RubySaml::Response.new(response_statuscode_responder)
      assert !response.send(:validate_success_status, true)
      assert response.errors.include? "The status code of the Response was not Success, was Responder"
    end

    it "return false when the status is not 'Success', and shows the StatusMessage" do
      response = OneLogin::RubySaml::Response.new(response_statuscode_responder_and_msg)
      assert !response.send(:validate_success_status, true)
      assert response.errors.include? "The status code of the Response was not Success, was Responder -> something_is_wrong"
    end

    it "return true when the status is 'Success'" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert response.send(:validate_success_status, true)
      assert_empty response.errors
    end
  end

  describe "#validate_conditions" do
    it "return false when encountering a condition that prevents the document from being valid" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      assert !response.send(:validate_conditions, true)
      assert /Current time is on or after NotOnOrAfter condition/.match(response.errors[0])
    end

    it "return true when encountering a condition that prevents the document from being valid" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert response.send(:validate_conditions, true)
      assert_empty response.errors
    end
  end

  describe "#validate_in_response_to" do
    it "return false when the inResponseTo value does not match the Request ID" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert !response.send(:validate_in_response_to, 'invalid_request_id', true)
      assert response.errors.include? "The InResponseTo of the Response: _fc4a34b0-7efb-012e-caae-782bcb13bb38, does not match the ID of the AuthNRequest sent by the SP: invalid_request_id"
    end

    it "return true when the inResponseTo value matches the Request ID" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert response.send(:validate_in_response_to, '_fc4a34b0-7efb-012e-caae-782bcb13bb38', true)
      assert_empty response.errors
    end      

    it "return true when no Request ID is provided for checking" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert response.send(:validate_in_response_to, nil, true)
      assert_empty response.errors
    end
  end

  describe "#validate_no_encrypted_attributes" do
    it "return false when the assertion contains encrypted attributes" do
      response = OneLogin::RubySaml::Response.new(response_encrypted_attrs)
      response.settings = settings
      assert !response.send(:validate_no_encrypted_attributes, true)
      assert response.errors.include? "There is an EncryptedAttribute in the Response and this SP not support them"
    end

    it "return true when the assertion does not contain encrypted attributes" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert response.send(:validate_no_encrypted_attributes, true)
      assert_empty response.errors
    end
  end

  describe "#validate_signed_elements" do
    it "return false when a lot of signed elements (more than 2)" do
      response = OneLogin::RubySaml::Response.new(response_multiple_signed)
      response.settings = settings
      assert !response.send(:validate_signed_elements)
      assert response.errors.include? "Found an unexpected number of Signature Element. SAML Response rejected"
    end

    it "return false when no signed elements" do
      response = OneLogin::RubySaml::Response.new(response_no_signed_elements)
      response.settings = settings
      assert !response.send(:validate_signed_elements)
      assert response.errors.include? "Found an unexpected number of Signature Element. SAML Response rejected"
    end

    it "return false when invalid signed elements" do
      response = OneLogin::RubySaml::Response.new(response_invalid_signed_element)
      response.settings = settings
      assert !response.send(:validate_signed_elements)
      assert response.errors.include? "Found an unexpected Signature Element. SAML Response rejected"
    end

    it "return true when there are the expected signed elements" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert response.send(:validate_signed_elements)
      assert_empty response.errors
    end
  end

  describe "#validate_audience" do
    it "return false when there is no valid audience" do
      response = OneLogin::RubySaml::Response.new(response_invalid_audience)
      response.settings = settings
      assert !response.send(:validate_audience)
      assert response.errors.include? "#{response.settings.issuer} is not a valid audience for this Response"
    end

    it "return true when the audience is valid" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      response.settings.issuer = '{audience}'
      assert response.send(:validate_audience)
      assert_empty response.errors
    end
  end

  describe "#validate_destination" do
    it "return false when the destination of the SAML Response does not match the assertion consumer service url" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      response.settings.assertion_consumer_service_url = 'invalid_acs'
      assert !response.send(:validate_destination)
      assert response.errors.include? "The response was received at #{response.destination} instead of #{response.settings.assertion_consumer_service_url}"
    end

    it "return true when the destination of the SAML Response matches the assertion consumer service url" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert response.send(:validate_destination)
      assert_empty response.errors
    end
  end

  describe "#validate_issuer" do
    it "return false when the issuer of the Message does not match the IdP entityId" do
      response = OneLogin::RubySaml::Response.new(response_invalid_issuer_message)
      response.settings = settings
      response.settings.idp_entity_id = 'http://idp.example.com/'
      assert !response.send(:validate_issuer)
      assert response.errors.include? "Doesn't match the issuer, expected: <#{response.settings.idp_entity_id}>, but was: <http://invalid.issuer.example.com/>"
    end

    it "return false when the issuer of the Assertion does not match the IdP entityId" do
      response = OneLogin::RubySaml::Response.new(response_invalid_issuer_assertion)
      response.settings = settings
      response.settings.idp_entity_id = 'http://idp.example.com/'
      assert !response.send(:validate_issuer)
      assert response.errors.include? "Doesn't match the issuer, expected: <#{response.settings.idp_entity_id}>, but was: <http://invalid.issuer.example.com/>"
    end

    it "return true when the issuer of the Message/Assertion matches the IdP entityId" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert response.send(:validate_issuer)

      response.settings.idp_entity_id = 'https://app.onelogin.com/saml2'
      assert response.send(:validate_issuer)        
    end
  end

  describe "#validate_subject_confirmation" do
    it "return false when no subject confirmation data" do
      response = OneLogin::RubySaml::Response.new(response_no_subjectconfirmation_data)
      response.settings = settings
      assert !response.send(:validate_subject_confirmation)
      assert response.errors.include? "A valid SubjectConfirmation was not found on this Response"
    end

    it "return false when no valid subject confirmation method" do
      response = OneLogin::RubySaml::Response.new(response_no_subjectconfirmation_method)
      response.settings = settings
      response.send(:validate_subject_confirmation)
      assert !response.send(:validate_subject_confirmation)
      assert response.errors.include? "A valid SubjectConfirmation was not found on this Response"
    end

    it "return false when invalid inresponse" do
      response = OneLogin::RubySaml::Response.new(response_invalid_subjectconfirmation_inresponse)
      response.settings = settings
      assert !response.send(:validate_subject_confirmation)
      assert response.errors.include? "A valid SubjectConfirmation was not found on this Response"
    end

    it "return false when invalid recipient" do
      response = OneLogin::RubySaml::Response.new(response_invalid_subjectconfirmation_recipient)
      response.settings = settings
      assert !response.send(:validate_subject_confirmation)
      assert response.errors.include? "A valid SubjectConfirmation was not found on this Response"
    end

    it "return false when invalid NotBefore" do
      response = OneLogin::RubySaml::Response.new(response_invalid_subjectconfirmation_nb)
      response.settings = settings
      assert !response.send(:validate_subject_confirmation)
      assert response.errors.include? "A valid SubjectConfirmation was not found on this Response"
    end

    it "return false when invalid NotOnOrAfter" do
      response = OneLogin::RubySaml::Response.new(response_invalid_subjectconfirmation_noa)
      response.settings = settings
      assert !response.send(:validate_subject_confirmation)
      assert response.errors.include? "A valid SubjectConfirmation was not found on this Response"
    end

    it "return true when valid subject confirmation" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      response.settings.assertion_consumer_service_url = 'recipient'
      assert response.send(:validate_subject_confirmation)
    end
  end

  describe "#validate_session_expiration" do
    it "return false when the session has expired" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      assert !response.send(:validate_session_expiration)
      assert response.errors.include? "The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response"
    end

    it "return true when the session has not expired" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.settings = settings
      assert response.send(:validate_session_expiration)
    end
  end

  describe "#is_valid?" do
    it "return false if settings have not been set" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      assert !response.is_valid?
      assert response.errors.include? "No settings on SAML Response"
    end

    it "return true when the response is initialized with valid data" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.stubs(:conditions).returns(nil)
      response.stubs(:validate_subject_confirmation).returns(true)
      assert !response.is_valid?
      assert response.errors.include? "No settings on SAML Response"
      settings = OneLogin::RubySaml::Settings.new
      assert !response.is_valid?
      assert response.errors.include? "No settings on SAML Response"       
      response.settings = settings
      assert !response.is_valid?
      assert response.errors.include? "No fingerprint or certificate on settings"
      settings.idp_cert_fingerprint = ruby_saml_cert_fingerprint
      assert response.is_valid?
    end

    it "should be idempotent when the response is initialized with invalid data" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.stubs(:conditions).returns(nil)
      response.stubs(:validate_subject_confirmation).returns(true)
      settings = OneLogin::RubySaml::Settings.new
      response.settings = settings
      assert !response.is_valid?
      assert response.errors.include? "No fingerprint or certificate on settings"
      assert !response.is_valid?
      assert response.errors.include? "No fingerprint or certificate on settings"
    end

    it "should be idempotent when the response is initialized with valid data" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.stubs(:conditions).returns(nil)
      response.stubs(:validate_subject_confirmation).returns(true)
      settings = OneLogin::RubySaml::Settings.new
      response.settings = settings
      settings.idp_cert_fingerprint = ruby_saml_cert_fingerprint
      assert response.is_valid?
      assert response.is_valid?
    end

    it "return true when using certificate instead of fingerprint" do
      response = OneLogin::RubySaml::Response.new(valid_signed_response)
      response.stubs(:conditions).returns(nil)
      response.stubs(:validate_subject_confirmation).returns(true)
      settings = OneLogin::RubySaml::Settings.new
      response.settings = settings
      settings.idp_cert = ruby_saml_cert_text
      assert response.is_valid?
    end

    it "not allow signature wrapping attack" do
      response = OneLogin::RubySaml::Response.new(response_document_4)
      response.stubs(:conditions).returns(nil)
      response.stubs(:validate_subject_confirmation).returns(true)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = signature_fingerprint_1
      response.settings = settings
      assert !response.is_valid?
    end

    it "support dynamic namespace resolution on signature elements" do
      response = OneLogin::RubySaml::Response.new(fixture("no_signature_ns.xml"))
      response.stubs(:conditions).returns(nil)
      response.stubs(:validate_subject_confirmation).returns(true)
      settings = OneLogin::RubySaml::Settings.new
      response.settings = settings
      settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
      XMLSecurity::SignedDocument.any_instance.expects(:validate_signature).returns(true)
      assert response.is_valid?
    end

    it "validate ADFS assertions" do
      response = OneLogin::RubySaml::Response.new(fixture(:adfs_response_sha256))
      response.stubs(:conditions).returns(nil)
      response.stubs(:validate_subject_confirmation).returns(true)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA"
      response.settings = settings
      assert response.is_valid?
    end

    it "validate the digest" do
      response = OneLogin::RubySaml::Response.new(r1_response_document_6)
      response.stubs(:conditions).returns(nil)
      response.stubs(:validate_session_expiration).returns(false)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert = r1_signature_2
      response.settings = settings
      assert !response.is_valid?
    end

    it "validate SAML 2.0 XML structure" do
      response = OneLogin::RubySaml::Response.new(response_invalid_signature_position)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = signature_fingerprint_1
      response.settings = settings
      assert !response.is_valid?
      assert response.errors.include? "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd"
    end

  end

  describe "#name_id" do
    it "extract the value of the name id element" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert_equal "support@onelogin.com", response.name_id

      response = OneLogin::RubySaml::Response.new(response_document_3)
      assert_equal "someone@example.com", response.name_id
    end

    it "be extractable from an OpenSAML response" do
      response = OneLogin::RubySaml::Response.new(fixture(:open_saml))
      assert_equal "someone@example.org", response.name_id
    end

    it "be extractable from a Simple SAML PHP response" do
      response = OneLogin::RubySaml::Response.new(fixture(:simple_saml_php))
      assert_equal "someone@example.com", response.name_id
    end
  end

  describe "#sessionindex" do
    it "extract the value of the sessionindex element" do
      response = OneLogin::RubySaml::Response.new(fixture(:simple_saml_php))
      assert_equal "_51be37965feb5579d803141076936dc2e9d1d98ebf", response.sessionindex
    end
  end

  describe "#get_fingerprint" do
    it "get the fingerprint value when cert and fingerprint in settings are nil" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      response.settings.idp_cert_fingerprint = nil
      response.settings.idp_cert = nil
      fingerprint = response.send(:get_fingerprint)
      assert_nil fingerprint
    end

    it "get the fingerprint value when there is a cert at the settings" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      response.settings.idp_cert_fingerprint = nil
      response.settings.idp_cert = ruby_saml_cert_text
      fingerprint = response.send(:get_fingerprint)
      assert fingerprint == ruby_saml_cert_fingerprint
    end

    it "get the fingerprint value when there is a fingerprint at the settings" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      response.settings.idp_cert_fingerprint = ruby_saml_cert_fingerprint
      response.settings.idp_cert = nil
      fingerprint = response.send(:get_fingerprint)
      assert fingerprint == ruby_saml_cert_fingerprint
    end

    it "get the fingerprint value when there are cert and fingerprint at the settings" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.settings = settings
      response.settings.idp_cert_fingerprint = ruby_saml_cert_fingerprint
      response.settings.idp_cert = ruby_saml_cert_text
      fingerprint = response.send(:get_fingerprint)
      assert fingerprint == ruby_saml_cert_fingerprint
    end
  end

  describe "#check_conditions" do
    it "check time conditions" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert !response.send(:validate_conditions, true)
      response = OneLogin::RubySaml::Response.new(response_document_6)
      assert response.send(:validate_conditions, true)
      time     = Time.parse("2011-06-14T18:25:01.516Z")
      Time.stubs(:now).returns(time)
      response = OneLogin::RubySaml::Response.new(response_document_5)
      assert response.send(:validate_conditions, true)
    end

    it "optionally allow for clock drift" do
      # The NotBefore condition in the document is 2011-06-14T18:21:01.516Z
      Time.stubs(:now).returns(Time.parse("2011-06-14T18:21:01Z"))
      response = OneLogin::RubySaml::Response.new(response_document_5, :allowed_clock_drift => 0.515)
      assert !response.send(:validate_conditions, true)

      Time.stubs(:now).returns(Time.parse("2011-06-14T18:21:01Z"))
      response = OneLogin::RubySaml::Response.new(response_document_5, :allowed_clock_drift => 0.516)
      assert response.send(:validate_conditions, true)
    end
  end

  describe "#attributes" do
    it "extract the first attribute in a hash accessed via its symbol" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert_equal "demo", response.attributes[:uid]
    end

    it "extract the first attribute in a hash accessed via its name" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert_equal "demo", response.attributes["uid"]
    end

    it "extract all attributes" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert_equal "demo", response.attributes[:uid]
      assert_equal "value", response.attributes[:another_value]
    end

    it "work for implicit namespaces" do
      response = OneLogin::RubySaml::Response.new(response_document_3)
      assert_equal "someone@example.com", response.attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
    end

    it "not raise errors about nil/empty attributes for EncryptedAttributes" do
      response = OneLogin::RubySaml::Response.new(response_document_7)
      assert_equal 'Demo', response.attributes["first_name"]
    end

    it "not raise on responses without attributes" do
      response = OneLogin::RubySaml::Response.new(response_document_4)
      assert_equal OneLogin::RubySaml::Attributes.new, response.attributes
    end
  end

  describe "#multiple values" do
    it "extract single value as string" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_equal "demo", response.attributes[:uid]
    end

    it "extract single value as string in compatibility mode off" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      OneLogin::RubySaml::Attributes.single_value_compatibility = false
      assert_equal ["demo"], response.attributes[:uid]
      # classes are not reloaded between tests so restore default
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    it "extract first of multiple values as string for b/w compatibility" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_equal 'value1', response.attributes[:another_value]
    end

    it "extract first of multiple values as string for b/w compatibility in compatibility mode off" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      OneLogin::RubySaml::Attributes.single_value_compatibility = false
      assert_equal ['value1', 'value2'], response.attributes[:another_value]
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    it "return array with all attributes when asked in XML order" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_equal ['value1', 'value2'], response.attributes.multi(:another_value)
    end

    it "return array with all attributes when asked in XML order in compatibility mode off" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      OneLogin::RubySaml::Attributes.single_value_compatibility = false
      assert_equal ['value1', 'value2'], response.attributes.multi(:another_value)
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    it "return first of multiple values when multiple Attribute tags in XML" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_equal 'role1', response.attributes[:role]
    end

    it "return first of multiple values when multiple Attribute tags in XML in compatibility mode off" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      OneLogin::RubySaml::Attributes.single_value_compatibility = false
      assert_equal ['role1', 'role2', 'role3'], response.attributes[:role]
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    it "return all of multiple values in reverse order when multiple Attribute tags in XML" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_equal ['role1', 'role2', 'role3'], response.attributes.multi(:role)
    end

    it "return all of multiple values in reverse order when multiple Attribute tags in XML in compatibility mode off" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      OneLogin::RubySaml::Attributes.single_value_compatibility = false
      assert_equal ['role1', 'role2', 'role3'], response.attributes.multi(:role)
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    it "return nil value correctly" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_nil response.attributes[:attribute_with_nil_value]
    end

    it "return nil value correctly when not in compatibility mode off" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      OneLogin::RubySaml::Attributes.single_value_compatibility = false
      assert_equal [nil], response.attributes[:attribute_with_nil_value]
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    it "return multiple values including nil and empty string" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_equal ["", "valuePresent", nil, nil], response.attributes.multi(:attribute_with_nils_and_empty_strings)
    end

    it "return multiple values from [] when not in compatibility mode off" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      OneLogin::RubySaml::Attributes.single_value_compatibility = false
      assert_equal ["", "valuePresent", nil, nil], response.attributes[:attribute_with_nils_and_empty_strings]
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    it "check what happens when trying retrieve attribute that does not exists" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_equal nil, response.attributes[:attribute_not_exists]
      assert_equal nil, response.attributes.single(:attribute_not_exists)
      assert_equal nil, response.attributes.multi(:attribute_not_exists)

      OneLogin::RubySaml::Attributes.single_value_compatibility = false
      assert_equal nil, response.attributes[:attribute_not_exists]
      assert_equal nil, response.attributes.single(:attribute_not_exists)
      assert_equal nil, response.attributes.multi(:attribute_not_exists)
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    it "Iterate over all attributes" do
      attrs = Hash.new
      attrs['uid'] = ['demo']
      attrs['another_value'] = ['value1', 'value2']
      attrs['role'] = ['role1', 'role2', 'role3']
      attrs['attribute_with_nil_value'] = [nil]
      attrs['attribute_with_nils_and_empty_strings'] = ['', 'valuePresent', nil, nil]

      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      response.attributes.each do |k,v|
        assert_equal attrs[k], v
      end
    end

    it "Replace values" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert_equal ['role1', 'role2', 'role3'], response.attributes.multi(:role)
      response.attributes.set('role', ['role4'])
      assert_equal ['role4'], response.attributes.multi(:role)
      response.attributes.set('role', 'role5')
      assert_equal 'role5', response.attributes.multi(:role)
    end

    it "Comparison" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      response_2 = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
      assert response.attributes == response_2.attributes
      response.attributes.set('role', ['role4'])
      assert !(response.attributes == response_2.attributes)
    end    
  end
     
  describe "#session_expires_at" do
    it "extract the value of the SessionNotOnOrAfter attribute" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert response.session_expires_at.is_a?(Time)

      response = OneLogin::RubySaml::Response.new(response_document_2)
      assert_nil response.session_expires_at
    end
  end

  describe "#issuer" do
    it "return the issuer inside the response assertion" do
      response = OneLogin::RubySaml::Response.new(response_document)
      assert_equal "https://app.onelogin.com/saml/metadata/13590", response.issuers[0]
    end

    it "return the issuer inside the response" do
      response = OneLogin::RubySaml::Response.new(response_document_2)
      assert_equal "wibble", response.issuers[0]
    end
  end

  describe "#success" do
    it "find a status code that says success" do
      response = OneLogin::RubySaml::Response.new(response_document)
      response.success?
    end
  end

  describe '#xpath_first_from_signed_assertion' do
    it 'not allow arbitrary code execution' do
      malicious_response_document = fixture('response_eval', false)
      response = OneLogin::RubySaml::Response.new(malicious_response_document)
      response.send(:xpath_first_from_signed_assertion)
      assert_equal($evalled, nil)
    end
  end

end

# frozen_string_literal: true

require_relative 'test_helper'
require 'ruby_saml/metadata'

class OneloginAliasTest < Minitest::Test

  describe 'legacy OneLogin namespace alias' do

    describe 'equality with Object' do
      it "should be equal" do
        assert_equal OneLogin, Object
        assert_equal ::OneLogin, Object
        assert_equal OneLogin::RubySaml, OneLogin::RubySaml
        assert_equal ::OneLogin::RubySaml, ::RubySaml
      end
    end

    describe 'Metadata' do
      let(:settings)          { OneLogin::RubySaml::Settings.new }
      let(:xml_text)          { OneLogin::RubySaml::Metadata.new.generate(settings, false) }
      let(:xml_doc)           { Nokogiri::XML(xml_text) }
      let(:spsso_descriptor)  { xml_doc.at_xpath("//md:SPSSODescriptor", { "md" => "urn:oasis:names:tc:SAML:2.0:metadata" }) }
      let(:acs)               { xml_doc.at_xpath("//md:AssertionConsumerService", { "md" => "urn:oasis:names:tc:SAML:2.0:metadata" }) }

      before do
        settings.sp_entity_id = "https://example.com"
        settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        settings.assertion_consumer_service_url = "https://foo.example/saml/consume"
      end

      it "generates Pretty Print Service Provider Metadata" do
        xml_text = OneLogin::RubySaml::Metadata.new.generate(settings, true)
        # assert correct xml declaration
        start = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor"
        assert_equal start, xml_text[0..start.length-1]
        assert_equal "https://example.com", xml_doc.at_xpath("//md:EntityDescriptor", { "md" => "urn:oasis:names:tc:SAML:2.0:metadata" })['entityID']
        assert_equal RubySaml::XML::NS_PROTOCOL, spsso_descriptor['protocolSupportEnumeration']
        assert_equal "false", spsso_descriptor['AuthnRequestsSigned']
        assert_equal "false", spsso_descriptor['WantAssertionsSigned']
        assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", xml_doc.at_xpath("//md:NameIDFormat", { "md" => "urn:oasis:names:tc:SAML:2.0:metadata" }).text.strip
        assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs['Binding']
        assert_equal "https://foo.example/saml/consume", acs['Location']
        assert validate_xml!(xml_text, "saml-schema-metadata-2.0.xsd")
      end
    end

    describe 'Attributes' do
      let(:attributes) do
        OneLogin::RubySaml::Attributes.new({
          'email' => %w[tom@hanks.com],
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname' => %w[Tom],
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname' => %w[Hanks]
        })
      end

      it 'fetches attributes' do
        assert_equal('tom@hanks.com', attributes.fetch('email'))
        assert_equal('tom@hanks.com', attributes.fetch(:email))
        assert_equal('Tom', attributes.fetch(/givenname/))
        assert_equal('Tom', attributes.fetch(/gi(.*)/))
        assert_nil(attributes.fetch(/^z.*/))
        assert_equal('Hanks', attributes.fetch(/surname/))
      end
    end

    describe "Response" do
      let(:settings) { OneLogin::RubySaml::Settings.new }
      let(:response) { OneLogin::RubySaml::Response.new(response_document_without_recipient) }
      let(:response_without_attributes) { OneLogin::RubySaml::Response.new(response_document_without_attributes) }
      let(:response_with_multiple_attribute_statements) { OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_statements)) }
      let(:response_without_reference_uri) { OneLogin::RubySaml::Response.new(response_document_without_reference_uri) }
      let(:response_with_signed_assertion) { OneLogin::RubySaml::Response.new(response_document_with_signed_assertion) }
      let(:response_with_ds_namespace_at_the_root) { OneLogin::RubySaml::Response.new(response_document_with_ds_namespace_at_the_root)}
      let(:response_unsigned) { OneLogin::RubySaml::Response.new(response_document_unsigned) }
      let(:response_wrapped) { OneLogin::RubySaml::Response.new(response_document_wrapped) }
      let(:response_multiple_attr_values) { OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values)) }
      let(:response_valid_signed) { OneLogin::RubySaml::Response.new(response_document_valid_signed) }
      let(:response_valid_signed_without_recipient) { OneLogin::RubySaml::Response.new(response_document_valid_signed, {:skip_recipient_check => true })}
      let(:response_valid_signed_without_x509certificate) { OneLogin::RubySaml::Response.new(response_document_valid_signed_without_x509certificate) }
      let(:response_no_id) { OneLogin::RubySaml::Response.new(read_invalid_response("no_id.xml.base64")) }
      let(:response_no_version) { OneLogin::RubySaml::Response.new(read_invalid_response("no_saml2.xml.base64")) }
      let(:response_multi_assertion) { OneLogin::RubySaml::Response.new(read_invalid_response("multiple_assertions.xml.base64")) }
      let(:response_no_conditions) { OneLogin::RubySaml::Response.new(read_invalid_response("no_conditions.xml.base64")) }
      let(:response_no_conditions_with_skip) { OneLogin::RubySaml::Response.new(read_invalid_response("no_conditions.xml.base64"), { :skip_conditions => true }) }
      let(:response_no_authnstatement) { OneLogin::RubySaml::Response.new(read_invalid_response("no_authnstatement.xml.base64")) }
      let(:response_no_authnstatement_with_skip) { OneLogin::RubySaml::Response.new(read_invalid_response("no_authnstatement.xml.base64"), {:skip_authnstatement => true}) }
      let(:response_empty_destination) { OneLogin::RubySaml::Response.new(read_invalid_response("empty_destination.xml.base64")) }
      let(:response_empty_destination_with_skip) { OneLogin::RubySaml::Response.new(read_invalid_response("empty_destination.xml.base64"), {:skip_destination => true}) }
      let(:response_no_status) { OneLogin::RubySaml::Response.new(read_invalid_response("no_status.xml.base64")) }
      let(:response_no_statuscode) { OneLogin::RubySaml::Response.new(read_invalid_response("no_status_code.xml.base64")) }
      let(:response_statuscode_responder) { OneLogin::RubySaml::Response.new(read_invalid_response("status_code_responder.xml.base64")) }
      let(:response_statuscode_responder_and_msg) { OneLogin::RubySaml::Response.new(read_invalid_response("status_code_responer_and_msg.xml.base64")) }
      let(:response_double_statuscode) { OneLogin::RubySaml::Response.new(response_document_double_status_code) }
      let(:response_encrypted_attrs) { OneLogin::RubySaml::Response.new(response_document_encrypted_attrs) }
      let(:response_no_signed_elements) { OneLogin::RubySaml::Response.new(read_invalid_response("no_signature.xml.base64")) }
      let(:response_multiple_signed) { OneLogin::RubySaml::Response.new(read_invalid_response("multiple_signed.xml.base64")) }
      let(:response_audience_self_closed) { OneLogin::RubySaml::Response.new(read_response("response_audience_self_closed_tag.xml.base64")) }
      let(:response_invalid_audience) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_audience.xml.base64")) }
      let(:response_invalid_audience_with_skip) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_audience.xml.base64"), {:skip_audience => true}) }
      let(:response_invalid_signed_element) { OneLogin::RubySaml::Response.new(read_invalid_response("response_invalid_signed_element.xml.base64")) }
      let(:response_invalid_issuer_assertion) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_issuer_assertion.xml.base64")) }
      let(:response_invalid_issuer_message) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_issuer_message.xml.base64")) }
      let(:response_no_issuer_response) { OneLogin::RubySaml::Response.new(read_invalid_response("no_issuer_response.xml.base64")) }
      let(:response_no_issuer_assertion) { OneLogin::RubySaml::Response.new(read_invalid_response("no_issuer_assertion.xml.base64")) }
      let(:response_no_nameid) { OneLogin::RubySaml::Response.new(read_invalid_response("no_nameid.xml.base64")) }
      let(:response_empty_nameid) { OneLogin::RubySaml::Response.new(read_invalid_response("empty_nameid.xml.base64")) }
      let(:response_wrong_spnamequalifier) { OneLogin::RubySaml::Response.new(read_invalid_response("wrong_spnamequalifier.xml.base64")) }
      let(:response_duplicated_attributes) { OneLogin::RubySaml::Response.new(read_invalid_response("duplicated_attributes.xml.base64")) }
      let(:response_no_subjectconfirmation_data) { OneLogin::RubySaml::Response.new(read_invalid_response("no_subjectconfirmation_data.xml.base64")) }
      let(:response_no_subjectconfirmation_method) { OneLogin::RubySaml::Response.new(read_invalid_response("no_subjectconfirmation_method.xml.base64")) }
      let(:response_invalid_subjectconfirmation_inresponse) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_subjectconfirmation_inresponse.xml.base64")) }
      let(:response_invalid_subjectconfirmation_recipient) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_subjectconfirmation_recipient.xml.base64")) }
      let(:response_invalid_subjectconfirmation_nb) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_subjectconfirmation_nb.xml.base64")) }
      let(:response_invalid_subjectconfirmation_noa) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_subjectconfirmation_noa.xml.base64")) }
      let(:response_invalid_signature_position) { OneLogin::RubySaml::Response.new(read_invalid_response("invalid_signature_position.xml.base64")) }
      let(:response_encrypted_nameid) { OneLogin::RubySaml::Response.new(response_document_encrypted_nameid) }

      def generate_audience_error(expected, actual)
        s = actual.count > 1 ? 's' : '';
        return "Invalid Audience#{s}. The audience#{s} #{actual.join(',')}, did not match the expected audience #{expected}"
      end

      it "raise an exception when response is initialized with nil" do
        assert_raises(ArgumentError) { OneLogin::RubySaml::Response.new(nil) }
      end

      it "not filter available options only" do
        options = { :skip_destination => true, :foo => :bar }
        response = OneLogin::RubySaml::Response.new(response_document_valid_signed, options)
        assert_includes response.options.keys, :skip_destination
        assert_includes response.options.keys, :foo
      end

      describe "Prevent node text with comment attack (VU#475445)" do
        before do
          @response = OneLogin::RubySaml::Response.new(read_response('response_node_text_attack.xml.base64'))
        end

        it "receives the full NameID when there is an injected comment" do
          assert_equal "support@onelogin.com", @response.name_id
        end

        it "receives the full AttributeValue when there is an injected comment" do
          assert_equal "smith", @response.attributes["surname"]
        end
      end

      describe "Another test to prevent with comment attack (VU#475445)" do
        before do
          @response = OneLogin::RubySaml::Response.new(read_response('response_node_text_attack2.xml.base64'), {:skip_recipient_check => true })
          @response.settings = settings
          @response.settings.idp_cert_fingerprint = ruby_saml_cert_fingerprint
        end

        it "receives the full NameID when there is an injected comment, validates the response" do
          assert_equal "test@onelogin.com", @response.name_id
        end
      end

      describe "Another test with CDATA injected" do
        before do
          @response = OneLogin::RubySaml::Response.new(read_response('response_node_text_attack3.xml.base64'), {:skip_recipient_check => true })
          @response.settings = settings
          @response.settings.idp_cert_fingerprint = ruby_saml_cert_fingerprint
        end

        it "it normalizes CDATA but reject SAMLResponse due signature invalidation" do
          assert_equal "test@onelogin.com.evil.com", @response.name_id
          assert !@response.is_valid?
          assert_includes @response.errors, "Invalid Signature on SAML Response"
        end
      end

      describe "Prevent XEE attack" do
        before do
          @response = OneLogin::RubySaml::Response.new(fixture(:attackxee))
        end

        it "false when evil attack vector is present, soft = true" do
          @response.soft = true
          assert !@response.send(:validate_structure)
          assert_includes @response.errors, "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd"
        end

        it "raise when evil attack vector is present, soft = false " do
          @response.soft = false

          assert_raises(OneLogin::RubySaml::ValidationError) do
            @response.send(:validate_structure)
          end
        end
      end
    end
  end
end

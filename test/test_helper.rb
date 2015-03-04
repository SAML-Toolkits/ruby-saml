require 'simplecov'

SimpleCov.start do
  add_filter "test/"
  add_filter "lib/onelogin/ruby-saml/logging.rb"
end

require 'rubygems'
require 'bundler'
require 'minitest/autorun'
require 'mocha/setup'

Bundler.require :default, :test

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'ruby-saml'

ENV["ruby-saml/testing"] = "1"

class Minitest::Test
  def fixture(document, base64 = true)
    response = Dir.glob(File.join(File.dirname(__FILE__), "responses", "#{document}*")).first
    if base64 && response =~ /\.xml$/
      Base64.encode64(File.read(response))
    else
      File.read(response)
    end
  end

  def response_document
    @response_document ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'response1.xml.base64'))
  end

  def response_document_xml
    @response_document ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'response1.xml'))
  end

  def response_document_2
    @response_document2 ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'response2.xml.base64'))
  end

  def response_document_3
    @response_document3 ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'response3.xml.base64'))
  end

  def response_document_4
    @response_document4 ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'response4.xml.base64'))
  end

  def response_document_5
    @response_document5 ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'response5.xml.base64'))
  end

  def r1_response_document_6
    @response_document6 ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'r1_response6.xml.base64'))
  end

  def ampersands_response
    @ampersands_response ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'response_with_ampersands.xml.base64'))
  end

  def response_document_6
    doc = Base64.decode64(response_document)
    doc.gsub!(/NotBefore=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotBefore=\"#{(Time.now-300).getutc.strftime("%Y-%m-%dT%XZ")}\"")
    doc.gsub!(/NotOnOrAfter=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotOnOrAfter=\"#{(Time.now+300).getutc.strftime("%Y-%m-%dT%XZ")}\"")
    Base64.encode64(doc)
  end

  def response_document_7
    @response_document7 ||= Base64.encode64(File.read(File.join(File.dirname(__FILE__), 'responses', 'response_no_cert_and_encrypted_attrs.xml')))
  end

  def valid_signed_response
    @valid_signed_response ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'valid_response.xml.base64'))
  end

  def response_no_id
    @response_no_id ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'no_id.xml.base64'))
  end

  def response_no_version
    @response_no_version ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'no_saml2.xml.base64'))
  end

  def response_multi_assertion
    @response_no_version ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'multiple_assertions.xml.base64'))
  end

  def response_no_status
    @response_no_status ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'no_status.xml.base64'))
  end

  def response_no_statuscode
    @response_no_statuscode ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'no_status_code.xml.base64'))
  end

  def response_statuscode_responder
    @response_statuscode_responder ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'status_code_responder.xml.base64'))
  end

  def response_statuscode_responder_and_msg
    @status_code_responer_and_msg ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'status_code_responer_and_msg.xml.base64'))
  end

  def response_encrypted_attrs
    @response_encrypted_attrs ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'response_encrypted_attrs.xml.base64')) 
  end

  def response_no_signed_elements
    @response_no_signed_elements ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'no_signature.xml.base64'))
  end

  def response_multiple_signed
    @response_no_signed_elements ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'multiple_signed.xml.base64'))
  end

  def response_invalid_audience
    @response_invalid_audience ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'invalid_audience.xml.base64'))
  end

  def response_invalid_signed_element
    @response_invalid_signed_element ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'response_invalid_signed_element.xml.base64'))
  end

  def response_invalid_issuer_assertion
    @response_invalid_issuer_assertion ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'invalid_issuer_assertion.xml.base64'))
  end

  def response_invalid_issuer_message
    @response_invalid_issuer_assertion ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'invalid_issuer_message.xml.base64'))
  end

  def response_no_subjectconfirmation_data
    @response_no_subjectconfirmation_data ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'no_subjectconfirmation_data.xml.base64'))
  end

  def response_no_subjectconfirmation_method
    @no_subjectconfirmation_method ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'no_subjectconfirmation_method.xml.base64'))
  end

  def response_invalid_subjectconfirmation_inresponse
    @response_invalid_subjectconfirmation_inresponse ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'invalid_subjectconfirmation_inresponse.xml.base64'))
  end

  def response_invalid_subjectconfirmation_recipient
    @response_invalid_subjectconfirmation_recipient ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'invalid_subjectconfirmation_recipient.xml.base64'))
  end

  def response_invalid_subjectconfirmation_nb
    @response_invalid_subjectconfirmation_nb ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'invalid_subjectconfirmation_nb.xml.base64'))
  end

  def response_invalid_subjectconfirmation_noa
    @response_invalid_subjectconfirmation_noa ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'invalid_subjectconfirmation_noa.xml.base64'))
  end

  def response_invalid_signature_position
    @response_invalid_signature_position ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'invalids', 'invalid_signature_position.xml.base64'))
  end

  def wrapped_response_2
    @wrapped_response_2 ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'wrapped_response_2.xml.base64'))
  end

  def signature_fingerprint_1
    @signature_fingerprint1 ||= "C5:19:85:D9:47:F1:BE:57:08:20:25:05:08:46:EB:27:F6:CA:B7:83"
  end

  def signature_1
    @signature1 ||= File.read(File.join(File.dirname(__FILE__), 'certificates', 'certificate1'))
  end

  def r1_signature_2
    @signature2 ||= File.read(File.join(File.dirname(__FILE__), 'certificates', 'r1_certificate2_base64'))
  end

  def idp_metadata
    @idp_metadata ||= File.read(File.join(File.dirname(__FILE__), 'metadata', 'idp_descriptor.xml'))
  end

  def idp_metadata_2
    @idp_metadata_2 ||= File.read(File.join(File.dirname(__FILE__), 'metadata', 'idp_descriptor_2.xml'))
  end

  def logout_request_xml
    @logout_request_xml ||= File.read(File.join(File.dirname(__FILE__), 'logout', 'slo_request.xml'))
  end

  def logout_request_xml_with_session_index
    @logout_request_xml_with_session_index ||= File.read(File.join(File.dirname(__FILE__), 'logout', 'slo_request_with_session_index.xml'))
  end

  def logout_request_base64
    @logout_request_base64 ||= File.read(File.join(File.dirname(__FILE__), 'logout', 'slo_request.xml.base64'))
  end

  def logout_request_deflated_base64
    @logout_request_deflated_base64 ||= File.read(File.join(File.dirname(__FILE__), 'logout', 'slo_request_deflated.xml.base64'))
  end

  def logout_request_document
    unless @logout_request_document
      xml = File.read(File.join(File.dirname(__FILE__), 'logout', 'slo_request.xml'))
      deflated = Zlib::Deflate.deflate(xml, 9)[2..-5]
      @logout_request_document = Base64.encode64(deflated)
    end
    @logout_request_document
  end

  def invalid_logout_request_document
    unless @invalid_logout_request_document
      xml = File.read(File.join(File.dirname(__FILE__), 'logout', 'invalid_slo_request.xml'))
      deflated = Zlib::Deflate.deflate(xml, 9)[2..-5]
      @invalid_logout_request_document = Base64.encode64(deflated)
    end
    @invalid_logout_request_document
  end

  def ruby_saml_cert
    @ruby_saml_cert ||= OpenSSL::X509::Certificate.new(ruby_saml_cert_text)
  end

  def ruby_saml_cert_fingerprint
    @ruby_saml_cert_fingerprint ||= Digest::SHA1.hexdigest(ruby_saml_cert.to_der).scan(/../).join(":").upcase
  end

  def ruby_saml_cert_text
    @ruby_saml_cert_text ||= File.read(File.join(File.dirname(__FILE__), 'certificates', 'ruby-saml.crt'))
  end

  def ruby_saml_key
    @ruby_saml_key ||= OpenSSL::PKey::RSA.new(ruby_saml_key_text)
  end

  def ruby_saml_key_text
    @ruby_saml_key_text ||= File.read(File.join(File.dirname(__FILE__), 'certificates', 'ruby-saml.key'))
  end

  #
  # logoutresponse fixtures
  #
  def random_id
    "_#{UUID.new.generate}"
  end

  #
  # decodes a base64 encoded SAML response for use in SloLogoutresponse tests
  #
  def decode_saml_response_payload(unauth_url)
    payload = CGI.unescape(unauth_url.split("SAMLResponse=").last)
    decoded = Base64.decode64(payload)

    zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    inflated = zstream.inflate(decoded)
    zstream.finish
    zstream.close
    inflated
  end

  #
  # decodes a base64 encoded SAML request for use in Logoutrequest tests
  #
  def decode_saml_request_payload(unauth_url)
    payload = CGI.unescape(unauth_url.split("SAMLRequest=").last)
    decoded = Base64.decode64(payload)

    zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    inflated = zstream.inflate(decoded)
    zstream.finish
    zstream.close
    inflated
  end
end

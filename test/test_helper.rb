require 'rubygems'
require 'bundler'
require 'test/unit'
require 'mocha/setup'

Bundler.require :default, :test

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'ruby-saml'

ENV["ruby-saml/testing"] = "1"

class Test::Unit::TestCase
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

  def wrapped_response_2
    @wrapped_response_2 ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'wrapped_response_2.xml.base64'))
  end

  def signed_message_encrypted_and_unsigned_assertion
    @signed_message_encrypted_and_unsigned_assertion ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'signed_message_encrypted_and_unsigned_assertion.xml.base64'))
  end

  def signed_message_encrypted_and_signed_assertion
    @signed_message_encrypted_and_signed_assertion ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'signed_message_encrypted_and_signed_assertion.xml.base64'))
  end

  def unsigned_message_encrypted_and_signed_assertion
    @unsigned_message_encrypted_and_signed_assertion ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'unsigned_message_encrypted_and_signed_assertion.xml.base64'))
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
    @idp_metadata ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'idp_descriptor.xml'))
  end

  def logout_request_document
    unless @logout_request_document
      xml = File.read(File.join(File.dirname(__FILE__), 'responses', 'slo_request.xml'))
      deflated = Zlib::Deflate.deflate(xml, 9)[2..-5]
      @logout_request_document = Base64.encode64(deflated)
    end
    @logout_request_document
  end

  def ruby_saml_cert
    @ruby_saml_cert ||= OpenSSL::X509::Certificate.new(ruby_saml_cert_text)
  end

  def ruby_saml_cert_fingerprint
    @ruby_saml_cert_fingerprint ||= Digest::SHA1.hexdigest(ruby_saml_cert.to_der).scan(/../).join(":")
  end

  def ruby_saml_cert_text
    File.read(File.join(File.dirname(__FILE__), 'certificates', 'ruby-saml.crt'))
  end

  def ruby_saml_cert2_text
    @ruby_saml_cert2_text ||= File.read(File.join(File.dirname(__FILE__), 'certificates', 'ruby-saml2.crt'))
  end

  def ruby_saml_key
    @ruby_saml_key ||= OpenSSL::PKey::RSA.new(ruby_saml_key_text)
  end

  def ruby_saml_key_text
    File.read(File.join(File.dirname(__FILE__), 'certificates', 'ruby-saml.key'))
  end

  def ruby_saml_key2_text
    @ruby_saml_key2_text ||= File.read(File.join(File.dirname(__FILE__), 'certificates', 'ruby-saml2.key'))
  end

end

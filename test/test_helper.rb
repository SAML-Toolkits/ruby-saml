require 'rubygems'
require 'bundler'
require 'minitest/autorun'
require 'mocha/setup'

Bundler.require :default, :test

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))

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

  def read_response(response)
    File.read(File.join(File.dirname(__FILE__), "responses", response))
  end

  def read_logout_request(request)
    File.read(File.join(File.dirname(__FILE__), "logout_requests", request))
  end

  def read_certificate(certificate)
    File.read(File.join(File.dirname(__FILE__), "certificates", certificate))
  end

  def response_document
    @response_document ||= read_response("response1.xml.base64")
  end

  def response_document_2
    @response_document2 ||= read_response("response2.xml.base64")
  end

  def response_document_3
    @response_document3 ||= read_response("response3.xml.base64")
  end

  def response_document_4
    @response_document4 ||= read_response("response4.xml.base64")
  end

  def response_document_5
    @response_document5 ||= read_response("response5.xml.base64")
  end

  def r1_response_document_6
    @response_document6 ||= read_response("r1_response6.xml.base64")
  end

  def ampersands_response
    @ampersands_response ||= read_response("response_with_ampersands.xml.base64")
  end

  def response_document_6
    doc = Base64.decode64(response_document)
    doc.gsub!(/NotBefore=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotBefore=\"#{(Time.now-300).getutc.strftime("%Y-%m-%dT%XZ")}\"")
    doc.gsub!(/NotOnOrAfter=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotOnOrAfter=\"#{(Time.now+300).getutc.strftime("%Y-%m-%dT%XZ")}\"")
    Base64.encode64(doc)
  end

  def response_document_7
    @response_document7 ||= Base64.encode64(read_response("response_no_cert_and_encrypted_attrs.xml"))
  end

  def wrapped_response_2
    @wrapped_response_2 ||= read_response("wrapped_response_2.xml.base64")
  end

  def signature_fingerprint_1
    @signature_fingerprint1 ||= "C5:19:85:D9:47:F1:BE:57:08:20:25:05:08:46:EB:27:F6:CA:B7:83"
  end

  def signature_1
    @signature1 ||= read_certificate("certificate1")
  end

  def r1_signature_2
    @signature2 ||= read_certificate("r1_certificate2_base64")
  end

  def idp_metadata
    @idp_metadata ||= read_response("idp_descriptor.xml")
  end

  def logout_request_document
    unless @logout_request_document
      xml = read_logout_request("slo_request.xml")
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
    read_certificate("ruby-saml.crt")
  end

  def ruby_saml_key
    @ruby_saml_key ||= OpenSSL::PKey::RSA.new(ruby_saml_key_text)
  end

  def ruby_saml_key_text
    read_certificate("ruby-saml.key")
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

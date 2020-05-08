require 'rubygems'
require 'minitest/autorun'
require 'shoulda'
require 'mocha/setup'
require 'timecop'

if RUBY_VERSION < '1.9'
  require 'uuid'
else
  require 'securerandom'
end

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

  def random_id
    RUBY_VERSION < '1.9' ? "_#{UUID.new.generate}" : "_#{SecureRandom.uuid}"
  end

  def read_response(response)
    File.read(File.join(File.dirname(__FILE__), "responses", response))
  end

  def read_certificate(certificate)
    File.read(File.join(File.dirname(__FILE__), "certificates", certificate))
  end

  def response_document
    @response_document ||= read_response('response1.xml.base64')
  end

  def response_document_2
    @response_document2 ||= read_response('response2.xml.base64')
  end

  def response_document_3
    @response_document3 ||= read_response('response3.xml.base64')
  end

  def response_document_4
    @response_document4 ||= read_response('response4.xml.base64')
  end

  def response_document_5
    @response_document5 ||= read_response('response5.xml.base64')
  end

  def r1_response_document_6
    @response_document6 ||= read_response('r1_response6.xml.base64')
  end

  def ampersands_response
    @ampersands_resposne ||= read_response('response_with_ampersands.xml.base64')
  end

  def response_document_6
    doc = Base64.decode64(response_document)
    doc.gsub!(/NotBefore=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotBefore=\"#{(Time.now-300).getutc.strftime("%Y-%m-%dT%XZ")}\"")
    doc.gsub!(/NotOnOrAfter=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotOnOrAfter=\"#{(Time.now+300).getutc.strftime("%Y-%m-%dT%XZ")}\"")
    Base64.encode64(doc)
  end

  def response_document_wrapped
    @response_document_wrapped ||= read_response("response_wrapped.xml.base64")
  end

  def response_document_valid_signed
    response_document_valid_signed ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'valid_response.xml.base64'))
  end

  def wrapped_response_2
    @wrapped_response_2 ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'wrapped_response_2.xml.base64'))
  end

  def signature_fingerprint_1
    @signature_fingerprint1 ||= "C5:19:85:D9:47:F1:BE:57:08:20:25:05:08:46:EB:27:F6:CA:B7:83"
  end

  def signature_fingerprint_valid_res
    @signature_fingerprint1 ||= "4b68c453c7d994aad9025c99d5efcf566287fe8d"
  end

  def signature_1
    @signature1 ||= read_certificate('certificate1')
  end

  def r1_signature_2
    @signature2 ||= read_certificate('r1_certificate2_base64')
  end

  def valid_cert
    @signature_valid_cert ||= read_certificate('ruby-saml.crt')
  end

  def valid_key
    @signature_valid_cert ||= read_certificate('ruby-saml.key')
  end

  def response_with_multiple_attribute_statements
    @response_with_multiple_attribute_statements = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_statements))
  end

  def response_multiple_attr_values
    @response_multiple_attr_values = OneLogin::RubySaml::Response.new(fixture(:response_with_multiple_attribute_values))
  end
end

def ruby_saml_cert_text
  read_certificate("ruby-saml.crt")
end

def ruby_saml_key_text
  read_certificate("ruby-saml.key")
end

def read_certificate(certificate)
  File.read(File.join(File.dirname(__FILE__), "certificates", certificate))
end

def decode_saml_request_payload(unauth_url)
  payload = CGI.unescape(unauth_url.split("SAMLRequest=").last)
  decoded = Base64.decode64(payload)

  zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
  inflated = zstream.inflate(decoded)
  zstream.finish
  zstream.close
  inflated
end

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

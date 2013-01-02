require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'mocha'
require 'ruby-debug'
require 'timecop'

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

  def ampersands_response
    @ampersands_resposne ||= File.read(File.join(File.dirname(__FILE__), 'responses', 'response_with_ampersands.xml.base64'))
  end

  def response_document_6
    doc = Base64.decode64(response_document)
    doc.gsub!(/NotBefore=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotBefore=\"#{(Time.now-300).getutc.strftime("%Y-%m-%dT%XZ")}\"")
    doc.gsub!(/NotOnOrAfter=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotOnOrAfter=\"#{(Time.now+300).getutc.strftime("%Y-%m-%dT%XZ")}\"")
    Base64.encode64(doc)
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

end

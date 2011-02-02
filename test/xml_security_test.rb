require 'test_helper'
require 'xml_security'

class XmlSecurityTest < Test::Unit::TestCase
  include XMLSecurity
  context "XmlSecurity" do
    setup do
      @document = XMLSecurity::SignedDocument.new(Base64.decode64(response_document))
    end

    should "should run validate without throwing NS related exceptions" do
      base64cert = @document.elements["//ds:X509Certificate"].text
      @document.validate_doc(base64cert, nil)
    end
  end
end

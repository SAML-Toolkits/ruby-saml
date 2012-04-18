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
      @document.validate_doc(base64cert, true)
    end
  end

  context "Digest" do
    should "validate using SHA256" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response, false))
      assert @document.validate("28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA")
    end
  end

end

require 'test_helper'
require 'xml_security'

class XmlSecurityTest < Test::Unit::TestCase
  include XMLSecurity

  context "XmlSecurity" do
    setup do
      @document = XMLSecurity::SignedDocument.new(Base64.decode64(response_document))
      @base64cert = @document.elements["//ds:X509Certificate"].text
    end

    should "should run validate without throwing NS related exceptions" do
      assert !@document.validate_doc(@base64cert, true)
    end

    should "should run validate with throwing NS related exceptions" do
      assert_raise(Onelogin::Saml::ValidationError) do
        @document.validate_doc(@base64cert, false)
      end
    end
    
    should "not raise an error when softly validating the document multiple times" do
      assert_nothing_raised do
        2.times { @document.validate_doc(@base64cert, true) }
      end
    end

    should "should raise Fingerprint mismatch" do
      exception = assert_raise(Onelogin::Saml::ValidationError) do
        @document.validate("no:fi:ng:er:pr:in:t", false)
      end
      assert_equal("Fingerprint mismatch", exception.message)
    end

    should "should raise Digest mismatch" do
      exception = assert_raise(Onelogin::Saml::ValidationError) do
        @document.validate_doc(@base64cert, false)
      end
      assert_equal("Digest mismatch", exception.message)
    end

    should "should raise Key validation error" do
      response = Base64.decode64(response_document)
      response.sub!("<ds:DigestValue>pJQ7MS/ek4KRRWGmv/H43ReHYMs=</ds:DigestValue>",
                    "<ds:DigestValue>b9xsAXLsynugg3Wc1CI3kpWku+0=</ds:DigestValue>")
      document = XMLSecurity::SignedDocument.new(response)
      base64cert = document.elements["//ds:X509Certificate"].text
      exception = assert_raise(Onelogin::Saml::ValidationError) do
        document.validate_doc(base64cert, false)
      end
      assert_equal("Key validation error", exception.message)
    end
  end

  context "Algorithms" do
    should "validate using SHA1" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha1, false))
      assert @document.validate("F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72")
    end

    should "validate using SHA256" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha256, false))
      assert @document.validate("28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA")
    end

    should "validate using SHA384" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha384, false))
      assert @document.validate("F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72")
    end

    should "validate using SHA512" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha512, false))
      assert @document.validate("F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72")
    end
  end
  
  context "XmlSecurity::SignedDocument" do
    
    context "#extract_inclusive_namespaces" do
      should "support explicit namespace resolution for exclusive canonicalization" do
        response = fixture(:open_saml_response, false)
        document = XMLSecurity::SignedDocument.new(response)
        inclusive_namespaces = document.send(:extract_inclusive_namespaces)
        
        assert_equal %w[ xs ], inclusive_namespaces
      end
      
      should "support implicit namespace resolution for exclusive canonicalization" do
        response = fixture(:no_signature_ns, false)
        document = XMLSecurity::SignedDocument.new(response)
        inclusive_namespaces = document.send(:extract_inclusive_namespaces)
        
        assert_equal %w[ #default saml ds xs xsi ], inclusive_namespaces
      end
      
      should "return an empty list when inclusive namespace element is missing" do
        response = fixture(:no_signature_ns, false)
        response.slice! %r{<InclusiveNamespaces xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="#default saml ds xs xsi"/>}
        
        document = XMLSecurity::SignedDocument.new(response)
        inclusive_namespaces = document.send(:extract_inclusive_namespaces)
        
        assert inclusive_namespaces.empty?
      end
    end
    
  end
  
end

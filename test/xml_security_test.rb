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
      assert !@document.validate_signature(@base64cert, true)
    end

    should "should run validate with throwing NS related exceptions" do
      assert_raise(OneLogin::RubySaml::ValidationError) do
        @document.validate_signature(@base64cert, false)
      end
    end

    should "not raise an error when softly validating the document multiple times" do
      assert_nothing_raised do
        2.times { @document.validate_signature(@base64cert, true) }
      end
    end

    should "not raise an error when softly validating the document and the X509Certificate is missing" do
      response = Base64.decode64(response_document)
      response.sub!(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "")
      document = XMLSecurity::SignedDocument.new(response)
      assert_nothing_raised do
        assert !document.validate_document("a fingerprint", true) # The fingerprint isn't relevant to this test
      end
    end

    should "should raise Fingerprint mismatch" do
      exception = assert_raise(OneLogin::RubySaml::ValidationError) do
        @document.validate_document("no:fi:ng:er:pr:in:t", false)
      end
      assert_equal("Fingerprint mismatch", exception.message)
      assert @document.errors.include? "Fingerprint mismatch"
    end

    should "should raise Digest mismatch" do
      exception = assert_raise(OneLogin::RubySaml::ValidationError) do
        @document.validate_signature(@base64cert, false)
      end
      assert_equal("Digest mismatch", exception.message)
      assert @document.errors.include? "Digest mismatch"
    end

    should "should raise Key validation error" do
      response = Base64.decode64(response_document)
      response.sub!("<ds:DigestValue>pJQ7MS/ek4KRRWGmv/H43ReHYMs=</ds:DigestValue>",
                    "<ds:DigestValue>b9xsAXLsynugg3Wc1CI3kpWku+0=</ds:DigestValue>")
      document = XMLSecurity::SignedDocument.new(response)
      base64cert = document.elements["//ds:X509Certificate"].text
      exception = assert_raise(OneLogin::RubySaml::ValidationError) do
        document.validate_signature(base64cert, false)
      end
      assert_equal("Key validation error", exception.message)
      assert document.errors.include? "Key validation error"
    end

    should "correctly obtain the digest method with alternate namespace declaration" do
      document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_xmlns, false))
      base64cert = document.elements["//X509Certificate"].text
      assert document.validate_signature(base64cert, false)
    end

    should "raise validation error when the X509Certificate is missing" do
      response = Base64.decode64(response_document)
      response.sub!(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "")
      document = XMLSecurity::SignedDocument.new(response)
      exception = assert_raise(OneLogin::RubySaml::ValidationError) do
        document.validate_document("a fingerprint", false) # The fingerprint isn't relevant to this test
      end
      assert_equal("Certificate element missing in response (ds:X509Certificate)", exception.message)
    end
  end

  context "Algorithms" do
    should "validate using SHA1" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha1, false))
      assert @document.validate_document("F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72")
    end

    should "validate using SHA256" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha256, false))
      assert @document.validate_document("28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA")
    end

    should "validate using SHA384" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha384, false))
      assert @document.validate_document("F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72")
    end

    should "validate using SHA512" do
      @document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha512, false))
      assert @document.validate_document("F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72")
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

      should_eventually 'support inclusive canonicalization' do

        response = OneLogin::RubySaml::Response.new(fixture("tdnf_response.xml"))
        response.stubs(:conditions).returns(nil)
        assert !response.is_valid?
        settings = OneLogin::RubySaml::Settings.new
        assert !response.is_valid?
        response.settings = settings
        assert !response.is_valid?
        settings.idp_cert_fingerprint = "e6 38 9a 20 b7 4f 13 db 6a bc b1 42 6a e7 52 1d d6 56 d4 1b".upcase.gsub(" ", ":")
        assert response.validate!
      end

      should "return an empty list when inclusive namespace element is missing" do
        response = fixture(:no_signature_ns, false)
        response.slice! %r{<InclusiveNamespaces xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="#default saml ds xs xsi"/>}

        document = XMLSecurity::SignedDocument.new(response)
        inclusive_namespaces = document.send(:extract_inclusive_namespaces)

        assert inclusive_namespaces.empty?
      end
    end

    context "XMLSecurity::DSIG" do
      should "sign a AuthNRequest" do
        settings = OneLogin::RubySaml::Settings.new({
          :idp_sso_target_url => "https://idp.example.com/sso",
          :protocol_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          :issuer => "https://sp.example.com/saml2",
          :assertion_consumer_service_url => "https://sp.example.com/acs"
        })

        request = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings)
        request.sign_document(ruby_saml_key, ruby_saml_cert)

        # verify our signature
        signed_doc = XMLSecurity::SignedDocument.new(request.to_s)
        signed_doc.validate_document(ruby_saml_cert_fingerprint, false)
      end

      should "sign a LogoutRequest" do
        settings = OneLogin::RubySaml::Settings.new({
          :idp_slo_target_url => "https://idp.example.com/slo",
          :protocol_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          :issuer => "https://sp.example.com/saml2",
          :single_logout_service_url => "https://sp.example.com/sls"
        })

        request = OneLogin::RubySaml::Logoutrequest.new.create_logout_request_xml_doc(settings)
        request.sign_document(ruby_saml_key, ruby_saml_cert)

        # verify our signature
        signed_doc = XMLSecurity::SignedDocument.new(request.to_s)
        signed_doc.validate_document(ruby_saml_cert_fingerprint, false)
      end

      should "sign a LogoutResponse" do
        settings = OneLogin::RubySaml::Settings.new({
          :idp_slo_target_url => "https://idp.example.com/slo",
          :protocol_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          :issuer => "https://sp.example.com/saml2",
          :single_logout_service_url => "https://sp.example.com/sls"
        })

        response = OneLogin::RubySaml::SloLogoutresponse.new.create_logout_response_xml_doc(settings, 'request_id_example', "Custom Logout Message")
        response.sign_document(ruby_saml_key, ruby_saml_cert)

        # verify our signature
        signed_doc = XMLSecurity::SignedDocument.new(response.to_s)
        signed_doc.validate_document(ruby_saml_cert_fingerprint, false)
      end
    end

    context "StarfieldTMS" do
      setup do
        @response = OneLogin::RubySaml::Response.new(fixture(:starfield_response))
        @response.settings = OneLogin::RubySaml::Settings.new(
                                                          :idp_cert_fingerprint => "8D:BA:53:8E:A3:B6:F9:F1:69:6C:BB:D9:D8:BD:41:B3:AC:4F:9D:4D"
                                                          )
      end

      should "be able to validate a good response" do
        Timecop.freeze Time.parse('2012-11-28 17:55:00 UTC') do
          assert @response.validate!
        end
      end

      should "fail before response is valid" do
        Timecop.freeze Time.parse('2012-11-20 17:55:00 UTC') do
          assert ! @response.is_valid?
        end
      end

      should "fail after response expires" do
        Timecop.freeze Time.parse('2012-11-30 17:55:00 UTC') do
          assert ! @response.is_valid?
        end
      end
    end

  end

end

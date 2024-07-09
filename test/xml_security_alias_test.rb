require_relative 'test_helper'
require 'ruby_saml/xml'

class XmlSecurityAliasTest < Minitest::Test

  describe "XmlSecurity alias to XMLSecurity" do
    let(:decoded_response) { Base64.decode64(response_document_without_recipient) }
    let(:document) { XMLSecurity::SignedDocument.new(decoded_response) }
    let(:settings) { RubySaml::Settings.new }

    before do
      @base64cert = document.elements["//ds:X509Certificate"].text
    end

    it "should run validate without throwing NS related exceptions" do
      assert !document.validate_signature(@base64cert, true)
    end

    it "should run validate with throwing NS related exceptions" do
      assert_raises(RubySaml::ValidationError) do
        document.validate_signature(@base64cert, false)
      end
    end

    it "not raise an error when softly validating the document multiple times" do
      2.times { assert_equal document.validate_signature(@base64cert, true), false }
    end

    it "not raise an error when softly validating the document and the X509Certificate is missing" do
      decoded_response.sub!(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "")
      mod_document = XMLSecurity::SignedDocument.new(decoded_response)
      assert !mod_document.validate_document("a fingerprint", true) # The fingerprint isn't relevant to this test
    end

    it "should raise Fingerprint mismatch" do
      exception = assert_raises(RubySaml::ValidationError) do
        document.validate_document("no:fi:ng:er:pr:in:t", false)
      end
      assert_equal("Fingerprint mismatch", exception.message)
      assert_includes document.errors, "Fingerprint mismatch"
    end

    it "should raise Digest mismatch" do
      exception = assert_raises(RubySaml::ValidationError) do
        document.validate_signature(@base64cert, false)
      end
      assert_equal("Digest mismatch", exception.message)
      assert_includes document.errors, "Digest mismatch"
    end

    it "should raise Key validation error" do
      decoded_response.sub!("<ds:DigestValue>pJQ7MS/ek4KRRWGmv/H43ReHYMs=</ds:DigestValue>",
                    "<ds:DigestValue>b9xsAXLsynugg3Wc1CI3kpWku+0=</ds:DigestValue>")
      mod_document = XMLSecurity::SignedDocument.new(decoded_response)
      base64cert = mod_document.elements["//ds:X509Certificate"].text
      exception = assert_raises(RubySaml::ValidationError) do
        mod_document.validate_signature(base64cert, false)
      end
      assert_equal("Key validation error", exception.message)
      assert_includes mod_document.errors, "Key validation error"
    end

    it "correctly obtain the digest method with alternate namespace declaration" do
      adfs_document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_xmlns, false))
      base64cert = adfs_document.elements["//X509Certificate"].text
      assert adfs_document.validate_signature(base64cert, false)
    end

    it "raise validation error when the X509Certificate is missing and no cert provided" do
      decoded_response.sub!(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "")
      mod_document = XMLSecurity::SignedDocument.new(decoded_response)
      exception = assert_raises(RubySaml::ValidationError) do
        mod_document.validate_document("a fingerprint", false) # The fingerprint isn't relevant to this test
      end
      assert_equal("Certificate element missing in response (ds:X509Certificate) and not cert provided at settings", exception.message)
    end

    it "invalidaties when the X509Certificate is missing and the cert is provided but mismatches" do
      decoded_response.sub!(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "")
      mod_document = XMLSecurity::SignedDocument.new(decoded_response)
      cert = OpenSSL::X509::Certificate.new(ruby_saml_cert)
      assert !mod_document.validate_document("a fingerprint", true, :cert => cert) # The fingerprint isn't relevant to this test
    end
  end

  describe "#canon_algorithm" do
    it "C14N_EXCLUSIVE_1_0" do
      canon_algorithm = Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      assert_equal canon_algorithm, XMLSecurity::BaseDocument.new.canon_algorithm("http://www.w3.org/2001/10/xml-exc-c14n#")
      assert_equal canon_algorithm, XMLSecurity::BaseDocument.new.canon_algorithm("http://www.w3.org/2001/10/xml-exc-c14n#WithComments")
    end
  end

  describe "#algorithm" do
    it "SHA256" do
      alg = OpenSSL::Digest::SHA256
      assert_equal alg, XMLSecurity::BaseDocument.new.algorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
      assert_equal alg, XMLSecurity::BaseDocument.new.algorithm("http://www.w3.org/2001/04/xmldsig-more#sha256")
      assert_equal alg, XMLSecurity::BaseDocument.new.algorithm("other")
    end
  end

  describe "Fingerprint Algorithms" do
    let(:response_fingerprint_test) { RubySaml::Response.new(fixture(:adfs_response_sha1, false)) }

    it "validate using SHA256" do
      sha256_fingerprint = "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21"
      sha256_fingerprint_downcase = sha256_fingerprint.tr(':', '').downcase

      assert response_fingerprint_test.document.validate_document(sha256_fingerprint)
      assert response_fingerprint_test.document.validate_document(sha256_fingerprint, true, fingerprint_alg: XMLSecurity::Document::SHA256)

      assert response_fingerprint_test.document.validate_document(sha256_fingerprint_downcase)
      assert response_fingerprint_test.document.validate_document(sha256_fingerprint_downcase, true, fingerprint_alg: XMLSecurity::Document::SHA256)
    end
  end

  describe "Signature Algorithms" do
    it "validate using SHA256" do
      document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_sha256, false))
      assert document.validate_document("3D:C5:BC:58:60:5D:19:64:94:E3:BA:C8:3D:49:01:D5:56:34:44:65:C2:85:0A:A8:65:A5:AC:76:7E:65:1F:F7")
    end
  end

  describe "XmlSecurity::SignedDocument" do

    describe "#extract_inclusive_namespaces" do
      it "support implicit namespace resolution for exclusive canonicalization" do
        response = fixture(:no_signature_ns, false)
        document = XMLSecurity::SignedDocument.new(response)
        inclusive_namespaces = document.send(:extract_inclusive_namespaces)

        assert_equal %w[ #default saml ds xs xsi ], inclusive_namespaces
      end

      it "return nil when inclusive namespace element is missing" do
        response = fixture(:no_signature_ns, false)
        response.slice! %r{<InclusiveNamespaces xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="#default saml ds xs xsi"/>}

        document = XMLSecurity::SignedDocument.new(response)
        inclusive_namespaces = document.send(:extract_inclusive_namespaces)

        assert inclusive_namespaces.nil?
      end
    end

    describe '#validate_document' do
      describe 'with valid document' do
        describe 'when response has signed message and assertion' do
          let(:document_data) { read_response('response_with_signed_message_and_assertion.xml') }
          let(:document) { RubySaml::Response.new(document_data).document }
          let(:fingerprint) { '6385109dd146a45d4382799491cb2707bd1ebda3738f27a0e4a4a8159c0fe6cd' }

          it 'is valid' do
            assert document.validate_document(fingerprint, true), 'Document should be valid'
          end
        end

        describe 'when response has signed assertion' do
          let(:document_data) { read_response('response_with_signed_assertion_3.xml') }
          let(:document) { RubySaml::Response.new(document_data).document }
          let(:fingerprint) { '6385109dd146a45d4382799491cb2707bd1ebda3738f27a0e4a4a8159c0fe6cd' }

          it 'is valid' do
            assert document.validate_document(fingerprint, true), 'Document should be valid'
          end
        end
      end

      describe 'signature_wrapping_attack' do
        let(:document_data) { read_invalid_response("signature_wrapping_attack.xml.base64") }
        let(:document) { RubySaml::Response.new(document_data).document }
        let(:fingerprint) { 'afe71c28ef740bc87425be13a2263d37971da1f9' }

        it 'is invalid' do
          assert !document.validate_document(fingerprint, true), 'Document should be invalid'
        end
      end

      describe 'signature wrapping attack - doubled SAML response body' do
        let(:document_data) { read_invalid_response("response_with_doubled_signed_assertion.xml") }
        let(:document) { RubySaml::Response.new(document_data) }
        let(:fingerprint) { '6385109dd146a45d4382799491cb2707bd1ebda3738f27a0e4a4a8159c0fe6cd' }

        it 'is valid, but the unsigned information is ignored in favour of the signed information' do
          assert document.document.validate_document(fingerprint, true), 'Document should be valid'
          assert_equal 'someone@example.org', document.name_id, 'Document should expose only signed, valid details'
        end
      end

      describe 'signature wrapping attack - concealed SAML response body' do
        let(:document_data) { read_invalid_response("response_with_concealed_signed_assertion.xml") }
        let(:document) { RubySaml::Response.new(document_data) }
        let(:fingerprint) { '6385109dd146a45d4382799491cb2707bd1ebda3738f27a0e4a4a8159c0fe6cd' }

        it 'is valid, but fails to retrieve information' do
          assert document.document.validate_document(fingerprint, true), 'Document should be valid'
          assert document.name_id.nil?, 'Document should expose only signed, valid details'
        end
      end
    end
  end
end

require_relative 'test_helper'
require 'ruby_saml/xml'

class XmlTest < Minitest::Test

  describe RubySaml::XML::SignedDocumentValidator do
    let(:decoded_response) { Base64.decode64(response_document_without_recipient) }
    let(:settings) { RubySaml::Settings.new }
    let(:errors) { [] }

    before do
      # Get the X509Certificate from the document for testing
      doc = Nokogiri::XML(decoded_response)
      @base64cert = doc.at_xpath("//ds:X509Certificate", { "ds" => "http://www.w3.org/2000/09/xmldsig#" }).text
    end

    it "should run validate without throwing NS related exceptions" do
      assert !RubySaml::XML::SignedDocumentValidator.validate_signature(decoded_response, @base64cert).is_a?(TrueClass)
    end

    it "should run validate with throwing NS related exceptions" do
      assert_raises(RubySaml::ValidationError) do
        RubySaml::XML::SignedDocumentValidator.validate_signature(decoded_response, @base64cert)
      end
    end

    it "not raise an error when softly validating the document multiple times" do
      2.times do
        assert_equal RubySaml::XML::SignedDocumentValidator.validate_signature(decoded_response, @base64cert, soft: true), false
      end
    end

    it "not raise an error when softly validating the document and the X509Certificate is missing" do
      modified_response = decoded_response.sub(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "")
      errors = []
      assert !RubySaml::XML::SignedDocumentValidator.validate_document(modified_response, "a fingerprint", true, {}, errors) # The fingerprint isn't relevant to this test
    end

    it "should raise Fingerprint mismatch" do
      errors = []
      exception = assert_raises(RubySaml::ValidationError) do
        RubySaml::XML::SignedDocumentValidator.validate_document(decoded_response, "no:fi:ng:er:pr:in:t", false, {}, errors)
      end
      assert_equal("Fingerprint mismatch", exception.message)
      assert_includes errors, "Fingerprint mismatch"
    end

    it "should raise Digest mismatch" do
      errors = []
      exception = assert_raises(RubySaml::ValidationError) do
        RubySaml::XML::SignedDocumentValidator.validate_signature(decoded_response, @base64cert, false, errors)
      end
      assert_equal("Digest mismatch", exception.message)
      assert_includes errors, "Digest mismatch"
    end

    it "should raise Key validation error" do
      modified_response = decoded_response.sub("<ds:DigestValue>pJQ7MS/ek4KRRWGmv/H43ReHYMs=</ds:DigestValue>",
                                               "<ds:DigestValue>b9xsAXLsynugg3Wc1CI3kpWku+0=</ds:DigestValue>")
      doc = Nokogiri::XML(modified_response)
      base64cert = doc.at_xpath("//ds:X509Certificate", { "ds" => "http://www.w3.org/2000/09/xmldsig#" }).text

      errors = []
      exception = assert_raises(RubySaml::ValidationError) do
        RubySaml::XML::SignedDocumentValidator.validate_signature(modified_response, base64cert, false, errors)
      end
      assert_equal("Key validation error", exception.message)
      assert_includes errors, "Key validation error"
    end

    it "correctly obtain the digest method with alternate namespace declaration" do
      adfs_document = fixture(:adfs_response_xmlns, false)
      doc = Nokogiri::XML(adfs_document)
      base64cert = doc.at_xpath("//X509Certificate").text

      errors = []
      assert RubySaml::XML::SignedDocumentValidator.validate_signature(adfs_document, base64cert, false, errors)
    end

    it "raise validation error when the X509Certificate is missing and no cert provided" do
      modified_response = decoded_response.sub(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "")

      errors = []
      exception = assert_raises(RubySaml::ValidationError) do
        RubySaml::XML::SignedDocumentValidator.validate_document(modified_response, "a fingerprint", false, {}, errors) # The fingerprint isn't relevant to this test
      end
      assert_equal("Certificate element missing in response (ds:X509Certificate) and not cert provided at settings", exception.message)
    end

    it "invalidaties when the X509Certificate is missing and the cert is provided but mismatches" do
      modified_response = decoded_response.sub(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "")
      cert = OpenSSL::X509::Certificate.new(ruby_saml_cert)

      errors = []
      assert !RubySaml::XML::SignedDocumentValidator.validate_document(modified_response, "a fingerprint", true, { cert: cert }, errors) # The fingerprint isn't relevant to this test
    end
  end

  describe "#canon_algorithm" do
    it "C14N_EXCLUSIVE_1_0" do
      canon_algorithm = Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      assert_equal canon_algorithm, RubySaml::XML::Crypto.canon_algorithm("http://www.w3.org/2001/10/xml-exc-c14n#")
      assert_equal canon_algorithm, RubySaml::XML::Crypto.canon_algorithm("http://www.w3.org/2001/10/xml-exc-c14n#WithComments")
      assert_equal canon_algorithm, RubySaml::XML::Crypto.canon_algorithm("other")
    end

    it "C14N_1_0" do
      canon_algorithm = Nokogiri::XML::XML_C14N_1_0
      assert_equal canon_algorithm, RubySaml::XML::Crypto.canon_algorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
      assert_equal canon_algorithm, RubySaml::XML::Crypto.canon_algorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments")
    end

    it "XML_C14N_1_1" do
      canon_algorithm = Nokogiri::XML::XML_C14N_1_1
      assert_equal canon_algorithm, RubySaml::XML::Crypto.canon_algorithm("http://www.w3.org/2006/12/xml-c14n11")
      assert_equal canon_algorithm, RubySaml::XML::Crypto.canon_algorithm("http://www.w3.org/2006/12/xml-c14n11#WithComments")
    end
  end

  describe "#algorithm" do
    it "SHA1" do
      alg = OpenSSL::Digest::SHA1
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1")
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("http://www.w3.org/2000/09/xmldsig#sha1")
    end

    it "SHA256" do
      alg = OpenSSL::Digest::SHA256
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("http://www.w3.org/2001/04/xmldsig-more#sha256")
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("other")
    end

    it "SHA384" do
      alg = OpenSSL::Digest::SHA384
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("http://www.w3.org/2001/04/xmldsig-more#sha384")
    end

    it "SHA512" do
      alg = OpenSSL::Digest::SHA512
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")
      assert_equal alg, RubySaml::XML::Crypto.hash_algorithm("http://www.w3.org/2001/04/xmldsig-more#sha512")
    end
  end

  describe 'Fingerprint Algorithms' do
    let(:response_fingerprint_test) { RubySaml::Response.new(fixture(:adfs_response_sha1, false)) }
    let(:document) { response_fingerprint_test.document }

    it 'validate using SHA1' do
      sha1_fingerprint = 'F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72'
      sha1_fingerprint_downcase = sha1_fingerprint.tr(':', '').downcase

      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, sha1_fingerprint, fingerprint_alg: RubySaml::XML::Crypto::SHA1)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, sha1_fingerprint_downcase, fingerprint_alg: RubySaml::XML::Crypto::SHA1)
    end

    it 'validate using SHA256' do
      sha256_fingerprint = 'C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21'
      sha256_fingerprint_downcase = sha256_fingerprint.tr(':', '').downcase

      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, sha256_fingerprint)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, sha256_fingerprint, fingerprint_alg: RubySaml::XML::Crypto::SHA256)

      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, sha256_fingerprint_downcase)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, sha256_fingerprint_downcase, fingerprint_alg: RubySaml::XML::Crypto::SHA256)
    end

    it 'validate using SHA384' do
      sha384_fingerprint = '98:FE:17:90:31:E7:68:18:8A:65:4D:DA:F5:76:E2:09:97:BE:8B:E3:7E:AA:8D:63:64:7C:0C:38:23:9A:AC:A2:EC:CE:48:A6:74:4D:E0:4C:50:80:40:B4:8D:55:14:14'

      assert !RubySaml::XML::SignedDocumentValidator.validate_document(document, sha384_fingerprint).is_a?(TrueClass)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, sha384_fingerprint, fingerprint_alg: RubySaml::XML::Crypto::SHA384)
    end

    it 'validate using SHA512' do
      sha512_fingerprint = '5A:AE:BA:D0:BA:9D:1E:25:05:01:1E:1A:C9:E9:FF:DB:ED:FA:6E:F7:52:EB:45:49:BD:DB:06:D8:A3:7E:CC:63:3A:04:A2:DD:DF:EE:61:05:D9:58:95:2A:77:17:30:4B:EB:4A:9F:48:4A:44:1C:D0:9E:0B:1E:04:77:FD:A3:D2'

      assert !RubySaml::XML::SignedDocumentValidator.validate_document(document, sha512_fingerprint).is_a?(TrueClass)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, sha512_fingerprint, fingerprint_alg: RubySaml::XML::Crypto::SHA512)
    end
  end

  describe 'Signature Algorithms' do
    it 'validate using SHA1' do
      document = fixture(:adfs_response_sha1, false)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, 'C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21')
    end

    it 'validate using SHA256' do
      document = fixture(:adfs_response_sha256, false)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, '3D:C5:BC:58:60:5D:19:64:94:E3:BA:C8:3D:49:01:D5:56:34:44:65:C2:85:0A:A8:65:A5:AC:76:7E:65:1F:F7')
    end

    it 'validate using SHA384' do
      document = fixture(:adfs_response_sha384, false)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, 'C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21')
    end

    it 'validate using SHA512' do
      document = fixture(:adfs_response_sha512, false)
      assert RubySaml::XML::SignedDocumentValidator.validate_document(document, 'C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21')
    end
  end

  describe 'RubySaml::XML::SignedDocument' do

    describe '#extract_inclusive_namespaces' do
      it 'support explicit namespace resolution for exclusive canonicalization' do
        document = fixture(:open_saml_response, false)
        inclusive_namespaces = RubySaml::XML::SignedDocumentValidator.send(:extract_inclusive_namespaces, document)

        assert_equal %w[ xs ], inclusive_namespaces
      end

      it 'support implicit namespace resolution for exclusive canonicalization' do
        document = fixture(:no_signature_ns, false)
        inclusive_namespaces = RubySaml::XML::SignedDocumentValidator.send(:extract_inclusive_namespaces, document)

        assert_equal %w[ #default saml ds xs xsi ], inclusive_namespaces
      end

      it 'support inclusive canonicalization' do
        skip('test not yet implemented')
        response = RubySaml::Response.new(fixture('tdnf_response.xml'))
        response.stubs(:conditions).returns(nil)
        assert !response.is_valid?
        assert !response.is_valid?
        response.settings = settings
        assert !response.is_valid?
        settings.idp_cert_fingerprint = 'e6 38 9a 20 b7 4f 13 db 6a bc b1 42 6a e7 52 1d d6 56 d4 1b'.upcase.gsub(' ', ':')
        assert response.is_valid?
      end

      it 'return nil when inclusive namespace element is missing' do
        document = fixture(:no_signature_ns, false)
        document.slice! %r{<InclusiveNamespaces xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="#default saml ds xs xsi"/>}
        inclusive_namespaces = RubySaml::XML::SignedDocumentValidator.send(:extract_inclusive_namespaces, document)

        assert inclusive_namespaces.nil?
      end
    end

    describe "RubySaml::XML::Crypto" do
      before do
        settings.idp_sso_service_url = "https://idp.example.com/sso"
        settings.protocol_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        settings.idp_slo_service_url = "https://idp.example.com/slo",
        settings.sp_entity_id = "https://sp.example.com/saml2"
        settings.assertion_consumer_service_url = "https://sp.example.com/acs"
        settings.single_logout_service_url = "https://sp.example.com/sls"
      end

      it "sign an AuthNRequest" do
        auth_request = RubySaml::Authrequest.new
        auth_request.assign_uuid(settings)
        request_doc = auth_request.create_xml_document(settings)

        # Use the DocumentSigner to sign the document
        signed_doc = RubySaml::XML::DocumentSigner.sign_document(
          request_doc,
          ruby_saml_key,
          ruby_saml_cert,
          RubySaml::XML::Crypto::RSA_SHA256,
          RubySaml::XML::Crypto::SHA256,
          auth_request.uuid
        )

        # Verify our signature using the static validator
        errors = []
        assert RubySaml::XML::SignedDocumentValidator.validate_document(
          signed_doc.to_s,
          ruby_saml_cert_fingerprint,
          false,
          {},
          errors
        )

        # Test with certificate as text
        auth_request2 = RubySaml::Authrequest.new
        auth_request2.assign_uuid(settings)
        request_doc2 = auth_request2.create_xml_document(settings)

        signed_doc2 = RubySaml::XML::DocumentSigner.sign_document(
          request_doc2,
          ruby_saml_key,
          ruby_saml_cert_text,
          RubySaml::XML::Crypto::RSA_SHA256,
          RubySaml::XML::Crypto::SHA256,
          auth_request2.uuid
        )

        errors2 = []
        assert RubySaml::XML::SignedDocumentValidator.validate_document(
          signed_doc2.to_s,
          ruby_saml_cert_fingerprint,
          false,
          {},
          errors2
        )
      end

      it "sign an AuthNRequest with certificate as text" do
        auth_request = RubySaml::Authrequest.new
        auth_request.assign_uuid(settings)
        request_doc = auth_request.create_xml_document(settings)

        signed_doc = RubySaml::XML::DocumentSigner.sign_document(
          request_doc,
          ruby_saml_key,
          ruby_saml_cert_text,
          RubySaml::XML::Crypto::RSA_SHA256,
          RubySaml::XML::Crypto::SHA256,
          auth_request.uuid
        )

        # Verify our signature
        errors = []
        assert RubySaml::XML::SignedDocumentValidator.validate_document(
          signed_doc.to_s,
          ruby_saml_cert_fingerprint,
          false,
          {},
          errors
        )
      end

      it "sign a LogoutRequest" do
        logout_request = RubySaml::Logoutrequest.new
        logout_request.assign_uuid(settings)
        request_doc = logout_request.create_xml_document(settings)

        signed_doc = RubySaml::XML::DocumentSigner.sign_document(
          request_doc,
          ruby_saml_key,
          ruby_saml_cert,
          RubySaml::XML::Crypto::RSA_SHA256,
          RubySaml::XML::Crypto::SHA256,
          logout_request.uuid
        )

        # Verify our signature
        errors = []
        assert RubySaml::XML::SignedDocumentValidator.validate_document(
          signed_doc.to_s,
          ruby_saml_cert_fingerprint,
          false,
          {},
          errors
        )

        logout_request2 = RubySaml::Logoutrequest.new
        logout_request2.assign_uuid(settings)
        request_doc2 = logout_request2.create_xml_document(settings)

        signed_doc2 = RubySaml::XML::DocumentSigner.sign_document(
          request_doc2,
          ruby_saml_key,
          ruby_saml_cert_text,
          RubySaml::XML::Crypto::RSA_SHA256,
          RubySaml::XML::Crypto::SHA256,
          logout_request2.uuid
        )

        # Verify our signature
        errors2 = []
        assert RubySaml::XML::SignedDocumentValidator.validate_document(
          signed_doc2.to_s,
          ruby_saml_cert_fingerprint,
          false,
          {},
          errors2
        )
      end

      it "sign a LogoutResponse" do
        logout_response = RubySaml::SloLogoutresponse.new
        logout_response.assign_uuid(settings)
        response_doc = logout_response.create_xml_document(settings, 'request_id_example', "Custom Logout Message")

        signed_doc = RubySaml::XML::DocumentSigner.sign_document(
          response_doc,
          ruby_saml_key,
          ruby_saml_cert,
          RubySaml::XML::Crypto::RSA_SHA256,
          RubySaml::XML::Crypto::SHA256,
          logout_response.uuid
        )

        # Verify our signature
        assert RubySaml::XML::SignedDocumentValidator.validate_document(
          signed_doc.to_s,
          ruby_saml_cert_fingerprint,
          soft: false
        ).is_a?(TrueClass)

        logout_response2 = RubySaml::SloLogoutresponse.new
        logout_response2.assign_uuid(settings)
        response_doc2 = logout_response2.create_xml_document(settings, 'request_id_example', "Custom Logout Message")

        signed_doc2 = RubySaml::XML::DocumentSigner.sign_document(
          response_doc2,
          ruby_saml_key,
          ruby_saml_cert_text,
          RubySaml::XML::Crypto::RSA_SHA256,
          RubySaml::XML::Crypto::SHA256,
          logout_response2.uuid
        )

        # Verify our signature
        assert RubySaml::XML::SignedDocumentValidator.validate_document(
          signed_doc2.to_s,
          ruby_saml_cert_fingerprint,
          soft: false
        ).is_a?(TrueClass)
      end
    end

    describe "StarfieldTMS" do
      let (:response) { RubySaml::Response.new(fixture(:starfield_response)) }

      before do
        response.settings = RubySaml::Settings.new(idp_cert_fingerprint: "8F:EB:0C:79:30:4A:E4:DF:B4:BD:7F:23:EE:29:3A:29:20:FE:BC:15:11:70:79:53:F4:37:55:05:2B:38:1A:42")
      end

      it "be able to validate a good response" do
        Timecop.freeze Time.parse('2012-11-28 17:55:00 UTC') do
          response.stubs(:validate_subject_confirmation).returns(true)
          assert response.is_valid?
        end
      end

      it "fail before response is valid" do
        Timecop.freeze Time.parse('2012-11-20 17:55:00 UTC') do
          assert !response.is_valid?

          time_1 = '2012-11-20 17:55:00 UTC < 2012-11-28 17:53:45 UTC'
          time_2 = 'Tue Nov 20 17:55:00 UTC 2012 < Wed Nov 28 17:53:45 UTC 2012'

          errors = [time_1, time_2].map do |time|
            "Current time is earlier than NotBefore condition (#{time} - 1s)"
          end

          assert_predicate(response.errors & errors, :any?)
        end
      end

      it "fail after response expires" do
        Timecop.freeze Time.parse('2012-11-30 17:55:00 UTC') do
          assert !response.is_valid?

          contains_expected_error = response.errors.include?("Current time is on or after NotOnOrAfter condition (2012-11-30 17:55:00 UTC >= 2012-11-28 18:33:45 UTC + 1s)")
          contains_expected_error ||= response.errors.include?("Current time is on or after NotOnOrAfter condition (Fri Nov 30 17:55:00 UTC 2012 >= Wed Nov 28 18:33:45 UTC 2012 + 1s)")
          assert contains_expected_error
        end
      end
    end

    describe '#validate_document' do
      let(:response) { RubySaml::Response.new(document_data) }
      let(:document) { response.document }

      describe 'with valid document' do
        describe 'when response has signed message and assertion' do
          let(:document_data) { read_response('response_with_signed_message_and_assertion.xml') }
          let(:fingerprint) { '6385109dd146a45d4382799491cb2707bd1ebda3738f27a0e4a4a8159c0fe6cd' }

          it 'is valid' do
            assert RubySaml::XML::SignedDocumentValidator.validate_document(document, fingerprint), 'Document should be valid'
          end
        end

        describe 'when response has signed assertion' do
          let(:document_data) { read_response('response_with_signed_assertion_3.xml') }
          let(:fingerprint) { '6385109dd146a45d4382799491cb2707bd1ebda3738f27a0e4a4a8159c0fe6cd' }

          it 'is valid' do
            assert RubySaml::XML::SignedDocumentValidator.validate_document(document, fingerprint), 'Document should be valid'
          end
        end
      end

      describe 'signature_wrapping_attack' do
        let(:document_data) { read_invalid_response("signature_wrapping_attack.xml.base64") }
        let(:fingerprint) { 'afe71c28ef740bc87425be13a2263d37971da1f9' }

        it 'is invalid' do
          assert !RubySaml::XML::SignedDocumentValidator.validate_document(document, fingerprint).is_a?(TrueClass), 'Document should be invalid'
        end
      end

      describe 'signature wrapping attack - doubled SAML response body' do
        let(:document_data) { read_invalid_response("response_with_doubled_signed_assertion.xml") }
        let(:fingerprint) { '6385109dd146a45d4382799491cb2707bd1ebda3738f27a0e4a4a8159c0fe6cd' }

        it 'is valid, but the unsigned information is ignored in favour of the signed information' do
          assert RubySaml::XML::SignedDocumentValidator.validate_document(document, fingerprint), 'Document should be valid'
          assert_equal 'someone@example.org', response.name_id, 'Document should expose only signed, valid details'
        end
      end

      describe 'signature wrapping attack - concealed SAML response body' do
        let(:document_data) { read_invalid_response("response_with_concealed_signed_assertion.xml") }
        let(:fingerprint) { '6385109dd146a45d4382799491cb2707bd1ebda3738f27a0e4a4a8159c0fe6cd' }

        it 'is valid, but fails to retrieve information' do
          assert RubySaml::XML::SignedDocumentValidator.validate_document(document, fingerprint), 'Document should be valid'
          assert response.name_id.nil?, 'Document should expose only signed, valid details'
        end
      end
    end

    describe '#validate_document_with_cert' do
      let(:document_data) { read_response('response_with_signed_message_and_assertion.xml') }
      let(:response) { RubySaml::Response.new(document_data) }
      let(:document) { response.document }
      let(:idp_cert) { OpenSSL::X509::Certificate.new(ruby_saml_cert_text) }
      let(:fingerprint) { '4b68c453c7d994aad9025c99d5efcf566287fe8d' }

      describe 'with invalid document ' do
        describe 'when certificate is invalid' do
          it 'is invalid' do
            wrong_document_data = document_data.sub(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, "<ds:X509Certificate>invalid<\/ds:X509Certificate>")
            wrong_document = RubySaml::Response.new(wrong_document_data).document
            refute RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(wrong_document, idp_cert).is_a?(TrueClass), 'Document should be invalid'
          end
        end
      end

      describe 'with valid document' do
        describe 'when response has cert' do
          it 'is valid' do
            assert RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(document, idp_cert), 'Document should be valid'
          end
        end

        describe 'when response has no cert but you have local cert' do
          let(:response) { RubySaml::Response.new(response_document_valid_signed_without_x509certificate) }
          let(:idp_cert) { OpenSSL::X509::Certificate.new(ruby_saml_cert_text) }

          it 'is valid' do
            assert RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(document, idp_cert), 'Document should be valid'
          end
        end
      end

      describe 'when response has no cert but you have local cert' do
        let(:document_data) { response_document_valid_signed_without_x509certificate }

        it 'is valid' do
          assert RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(document, idp_cert), 'Document should be valid'
        end
      end

      describe 'when response cert is invalid' do
        let(:document_data) do
          contents = read_response('response_with_signed_message_and_assertion.xml')
          contents.sub(/<ds:X509Certificate>.*<\/ds:X509Certificate>/,
                       "<ds:X509Certificate>an-invalid-certificate</ds:X509Certificate>")
        end

        it 'is not valid' do
          assert !RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(document, idp_cert).is_a?(TrueClass), 'Document should be valid'
          errors = [RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(document, idp_cert)]
          assert_equal(["Document Certificate Error"], errors)
        end
      end

      describe 'when response cert is different from idp cert' do
        let(:idp_cert) { OpenSSL::X509::Certificate.new(ruby_saml_cert_text2) }

        it 'is not valid' do
          exception = assert_raises(RubySaml::ValidationError) do
            RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(document, idp_cert)
          end
          assert_equal("Certificate of the Signature element does not match provided certificate", exception.message)
        end

        it 'is not valid (soft = true)' do
          errors = [RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(document, idp_cert)]
          assert_equal(["Certificate of the Signature element does not match provided certificate"], errors)
        end
      end
    end
  end
end

# frozen_string_literal: true

require_relative 'test_helper'

class UtilsTest < Minitest::Test
  describe ".parse_duration" do
    DURATIONS_FROM_EPOCH = {
      # Basic formats
      "P1Y1M1D"        => "1971-02-02T00:00:00.000Z",
      "PT1H1M1S"       => "1970-01-01T01:01:01.000Z",
      "P1W"            => "1970-01-08T00:00:00.000Z",
      "P1Y1M1DT1H1M1S" => "1971-02-02T01:01:01.000Z",

      # Negative duration
      "-P1Y1M1DT1H1M1S" => "1968-11-29T22:58:59.000Z",

      # Nominal wraparounds
      "P13M" => "1971-02-01T00:00:00.000Z",
      "P31D" => "1970-02-01T00:00:00.000Z",

      # Decimal seconds
      "PT0.5S" => "1970-01-01T00:00:00.500Z",
      "PT0,5S" => "1970-01-01T00:00:00.500Z"
    }

    def result(duration, reference = 0)
      Time.at(
        RubySaml::Utils.parse_duration(duration, reference)
      ).utc.iso8601(3)
    end

    DURATIONS_FROM_EPOCH.each do |duration, expected|
      it "parses #{duration} to return #{expected} from the given timestamp" do
        assert_equal expected, result(duration)
      end
    end

    it "returns the last calendar day of the next month when advancing from a longer month to a shorter one" do
      initial_timestamp = Time.iso8601("1970-01-31T00:00:00.000Z").to_i
      assert_equal "1970-02-28T00:00:00.000Z", result("P1M", initial_timestamp)
    end
  end

  describe ".format_cert" do
    let(:formatted_certificate) { read_certificate("formatted_certificate") }
    let(:formatted_chained_certificate) { read_certificate("formatted_chained_certificate") }

    it "returns empty string when the cert is an empty string" do
      cert = ''
      assert_equal '', RubySaml::Utils.format_cert(cert)
    end

    it "returns nil when the cert is nil" do
      cert = nil
      assert_nil RubySaml::Utils.format_cert(cert)
    end

    it "returns the certificate when it is valid" do
      assert_equal formatted_certificate, RubySaml::Utils.format_cert(formatted_certificate)
    end

    it "reformats the certificate when there are spaces and no line breaks" do
      invalid_certificate1 = read_certificate("invalid_certificate1")
      assert_equal formatted_certificate, RubySaml::Utils.format_cert(invalid_certificate1)
    end

    it "reformats the certificate when there are spaces and no headers" do
      invalid_certificate2 = read_certificate("invalid_certificate2")
      assert_equal formatted_certificate, RubySaml::Utils.format_cert(invalid_certificate2)
    end

    it "returns the original cert when it's encoded" do
      encoded_certificate = read_certificate("certificate.der")
      assert_equal encoded_certificate, RubySaml::Utils.format_cert(encoded_certificate)
    end

    it "reformats the certificate when there line breaks and no headers" do
      invalid_certificate3 = read_certificate("invalid_certificate3")
      assert_equal formatted_certificate, RubySaml::Utils.format_cert(invalid_certificate3)
    end

    it "returns the chained certificate when it is a valid chained certificate" do
      assert_equal formatted_chained_certificate, RubySaml::Utils.format_cert(formatted_chained_certificate)
    end

    it "reformats the chained certificate when there are spaces and no line breaks" do
      invalid_chained_certificate1 = read_certificate("invalid_chained_certificate1")
      assert_equal formatted_chained_certificate, RubySaml::Utils.format_cert(invalid_chained_certificate1)
    end
  end

  describe ".format_private_key" do
    let(:formatted_private_key) do
      read_certificate("formatted_private_key")
    end

    it "returns empty string when the private key is an empty string" do
      private_key = ''
      assert_equal '', RubySaml::Utils.format_private_key(private_key)
    end

    it "returns nil when the private key is nil" do
      private_key = nil
      assert_nil RubySaml::Utils.format_private_key(private_key)
    end

    it "returns the private key when it is valid" do
      assert_equal formatted_private_key, RubySaml::Utils.format_private_key(formatted_private_key)
    end

    it "reformats the private key when there are spaces and no line breaks" do
      invalid_private_key1 = read_certificate("invalid_private_key1")
      assert_equal formatted_private_key, RubySaml::Utils.format_private_key(invalid_private_key1)
    end

    it "reformats the private key when there are spaces and no headers" do
      invalid_private_key2 = read_certificate("invalid_private_key2")
      assert_equal formatted_private_key, RubySaml::Utils.format_private_key(invalid_private_key2)
    end

    it "reformats the private key when there line breaks and no headers" do
      invalid_private_key3 = read_certificate("invalid_private_key3")
      assert_equal formatted_private_key, RubySaml::Utils.format_private_key(invalid_private_key3)
    end

    describe "an RSA public key" do
      let(:formatted_rsa_private_key) do
        read_certificate("formatted_rsa_private_key")
      end

      it "returns the private key when it is valid" do
        assert_equal formatted_rsa_private_key, RubySaml::Utils.format_private_key(formatted_rsa_private_key)
      end

      it "reformats the private key when there are spaces and no line breaks" do
        invalid_rsa_private_key1 = read_certificate("invalid_rsa_private_key1")
        assert_equal formatted_rsa_private_key, RubySaml::Utils.format_private_key(invalid_rsa_private_key1)
      end

      it "reformats the private key when there are spaces and no headers" do
        invalid_rsa_private_key2 = read_certificate("invalid_rsa_private_key2")
        assert_equal formatted_private_key, RubySaml::Utils.format_private_key(invalid_rsa_private_key2)
      end

      it "reformats the private key when there line breaks and no headers" do
        invalid_rsa_private_key3 = read_certificate("invalid_rsa_private_key3")
        assert_equal formatted_private_key, RubySaml::Utils.format_private_key(invalid_rsa_private_key3)
      end
    end
  end

  describe '.build_cert_object' do
    each_key_algorithm do |algorithm|
      it 'returns a certificate object for valid certificate string' do
        pem = CertificateHelper.generate_cert(algorithm).to_pem
        cert_object = RubySaml::Utils.build_cert_object(pem)
        assert_instance_of OpenSSL::X509::Certificate, cert_object
      end
    end

    it 'returns the original certificate when an OpenSSL::X509::Certificate is given' do
      certificate = OpenSSL::X509::Certificate.new
      assert_same certificate, RubySaml::Utils.build_cert_object(certificate)
    end

    it 'returns nil for nil certificate string' do
      assert_nil RubySaml::Utils.build_cert_object(nil)
    end

    it 'returns nil for empty certificate string' do
      assert_nil RubySaml::Utils.build_cert_object('')
    end

    it 'raises error when given an invalid certificate string' do
      assert_raises OpenSSL::X509::CertificateError do
        RubySaml::Utils.build_cert_object('Foobar')
      end
    end
  end

  describe '.build_private_key_object' do
    each_key_algorithm do |algorithm|
      it 'returns a private key object for valid private key string' do
        pem = CertificateHelper.generate_private_key(algorithm).to_pem
        private_key_object = RubySaml::Utils.build_private_key_object(pem)
        assert_instance_of(expected_key_class(algorithm), private_key_object)
      end
    end

    [OpenSSL::PKey::RSA, OpenSSL::PKey::DSA, OpenSSL::PKey::EC].each do |key_class|
      it 'returns the original private key when an instance of OpenSSL::PKey::PKey is given' do
        private_key = key_class.new
        assert_same private_key, RubySaml::Utils.build_private_key_object(private_key)
      end
    end

    it 'returns nil for nil private key string' do
      assert_nil RubySaml::Utils.build_private_key_object(nil)
    end

    it 'returns nil for empty private key string' do
      assert_nil RubySaml::Utils.build_private_key_object('')
    end

    it 'raises error when given an invalid private key string' do
      assert_raises OpenSSL::PKey::RSAError do
        RubySaml::Utils.build_private_key_object('Foobar')
      end
    end
  end

  describe ".build_query" do
    it "returns the query string" do
      params = {}
      params[:type] = "SAMLRequest"
      params[:data] = "PHNhbWxwOkF1dGhuUmVxdWVzdCBEZXN0aW5hdGlvbj0naHR0cDovL2V4YW1wbGUuY29tP2ZpZWxkPXZhbHVlJyBJRD0nXzk4NmUxZDEwLWVhY2ItMDEzMi01MGRkLTAwOTBmNWRlZGQ3NycgSXNzdWVJbnN0YW50PScyMDE1LTA2LTAxVDIwOjM0OjU5WicgVmVyc2lvbj0nMi4wJyB4bWxuczpzYW1sPSd1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uJyB4bWxuczpzYW1scD0ndXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sJy8+"
      params[:relay_state] = "http://example.com"
      params[:sig_alg] = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
      query_string = RubySaml::Utils.build_query(params)
      assert_equal "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdCBEZXN0aW5hdGlvbj0naHR0cDovL2V4YW1wbGUuY29tP2ZpZWxkPXZhbHVlJyBJRD0nXzk4NmUxZDEwLWVhY2ItMDEzMi01MGRkLTAwOTBmNWRlZGQ3NycgSXNzdWVJbnN0YW50PScyMDE1LTA2LTAxVDIwOjM0OjU5WicgVmVyc2lvbj0nMi4wJyB4bWxuczpzYW1sPSd1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uJyB4bWxuczpzYW1scD0ndXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sJy8%2B&RelayState=http%3A%2F%2Fexample.com&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256", query_string
    end
  end

  describe ".verify_signature" do
    before do
      @params = {}
      @params[:cert] = ruby_saml_cert
      @params[:sig_alg] = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
      @params[:query_string] = "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdCBEZXN0aW5hdGlvbj0naHR0cDovL2V4YW1wbGUuY29tP2ZpZWxkPXZhbHVlJyBJRD0nXzk4NmUxZDEwLWVhY2ItMDEzMi01MGRkLTAwOTBmNWRlZGQ3NycgSXNzdWVJbnN0YW50PScyMDE1LTA2LTAxVDIwOjM0OjU5WicgVmVyc2lvbj0nMi4wJyB4bWxuczpzYW1sPSd1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uJyB4bWxuczpzYW1scD0ndXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sJy8%2B&RelayState=http%3A%2F%2Fexample.com&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1"
    end

    it "returns true when the signature is valid" do
      @params[:signature] = "uWJm/T4gKLYEsVu1j/ZmjDeHp9zYPXPXWTXHFJZf2KKnWg57fUw3x2l6KTyRQ+Xjigb+sfYdGnnwmIz6KngXYRnh7nO6inspRLWOwkqQFy9iR9LDlMcfpXV/0g3oAxBxO6tX8MUHqR2R62SYZRGd1rxC9apg4vQiP97+atOI8t4="
      assert RubySaml::Utils.verify_signature(@params)
    end

    it "returns false when the signature is invalid" do
      @params[:signature] = "uWJm/InVaLiDsVu1j/ZmjDeHp9zYPXPXWTXHFJZf2KKnWg57fUw3x2l6KTyRQ+Xjigb+sfYdGnnwmIz6KngXYRnh7nO6inspRLWOwkqQFy9iR9LDlMcfpXV/0g3oAxBxO6tX8MUHqR2R62SYZRGd1rxC9apg4vQiP97+atOI8t4="
      assert !RubySaml::Utils.verify_signature(@params)
    end
  end

  describe ".status_error_msg" do
    it "returns a error msg with status_code and status message" do
      error_msg = "The status code of the Logout Response was not Success"
      status_code = "urn:oasis:names:tc:SAML:2.0:status:Requester"
      status_message = "The request could not be performed due to an error on the part of the requester."
      status_error_msg = RubySaml::Utils.status_error_msg(error_msg, status_code, status_message)
      assert_equal "The status code of the Logout Response was not Success, was Requester -> The request could not be performed due to an error on the part of the requester.", status_error_msg
    end

    it "returns a error msg with status_code" do
      error_msg = "The status code of the Logout Response was not Success"
      status_code = "urn:oasis:names:tc:SAML:2.0:status:Requester"
      status_error_msg = RubySaml::Utils.status_error_msg(error_msg, status_code)
      assert_equal "The status code of the Logout Response was not Success, was Requester", status_error_msg
    end

    it "returns a error msg" do
      error_msg = "The status code of the Logout Response was not Success"
      status_error_msg = RubySaml::Utils.status_error_msg(error_msg)
      assert_equal "The status code of the Logout Response was not Success", status_error_msg
    end
  end

  describe "Utils" do

    describe ".uuid" do
      it "returns a uuid starting with an underscore" do
        assert_match(/^_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, RubySaml::Utils.uuid)
      end

      it "doesn't return the same value twice" do
        refute_equal RubySaml::Utils.uuid, RubySaml::Utils.uuid
      end
    end

    describe '.uri_match?' do
      it 'matches two urls' do
        destination = 'http://www.example.com/test?var=stuff'
        settings = 'http://www.example.com/test?var=stuff'
        assert RubySaml::Utils.uri_match?(destination, settings)
      end

      it 'fails to match two urls' do
        destination = 'http://www.example.com/test?var=stuff'
        settings = 'http://www.example.com/othertest?var=stuff'
        assert !RubySaml::Utils.uri_match?(destination, settings)
      end

      it "matches two URLs if the scheme case doesn't match" do
        destination = 'http://www.example.com/test?var=stuff'
        settings = 'HTTP://www.example.com/test?var=stuff'
        assert RubySaml::Utils.uri_match?(destination, settings)
      end

      it "matches two URLs if the host case doesn't match" do
        destination = 'http://www.EXAMPLE.com/test?var=stuff'
        settings = 'http://www.example.com/test?var=stuff'
        assert RubySaml::Utils.uri_match?(destination, settings)
      end

      it "fails to match two URLs if the path case doesn't match" do
        destination = 'http://www.example.com/TEST?var=stuff'
        settings = 'http://www.example.com/test?var=stuff'
        assert !RubySaml::Utils.uri_match?(destination, settings)
      end

      it "fails to match two URLs if the query case doesn't match" do
        destination = 'http://www.example.com/test?var=stuff'
        settings = 'http://www.example.com/test?var=STUFF'
        assert !RubySaml::Utils.uri_match?(destination, settings)
      end

      it 'matches two non urls' do
        destination = 'stuff'
        settings = 'stuff'
        assert RubySaml::Utils.uri_match?(destination, settings)
      end

      it "fails to match two non urls" do
        destination = 'stuff'
        settings = 'not stuff'
        assert !RubySaml::Utils.uri_match?(destination, settings)
      end
    end

    describe '.element_text' do
      it 'returns the element text' do
        element = REXML::Document.new('<element>element text</element>').elements.first
        assert_equal 'element text', RubySaml::Utils.element_text(element)
      end

      it 'returns all segments of the element text' do
        element = REXML::Document.new('<element>element <!-- comment -->text</element>').elements.first
        assert_equal 'element text', RubySaml::Utils.element_text(element)
      end

      it 'returns normalized element text' do
        element = REXML::Document.new('<element>element &amp; text</element>').elements.first
        assert_equal 'element & text', RubySaml::Utils.element_text(element)
      end

      it 'returns the CDATA element text' do
        element = REXML::Document.new('<element><![CDATA[element & text]]></element>').elements.first
        assert_equal 'element & text', RubySaml::Utils.element_text(element)
      end

      it 'returns the element text with newlines and additional whitespace' do
        element = REXML::Document.new("<element>  element \n text  </element>").elements.first
        assert_equal "  element \n text  ", RubySaml::Utils.element_text(element)
      end

      it 'returns nil when element is nil' do
        assert_nil RubySaml::Utils.element_text(nil)
      end

      it 'returns empty string when element has no text' do
        element = REXML::Document.new('<element></element>').elements.first
        assert_equal '', RubySaml::Utils.element_text(element)
      end
    end
  end

  describe '.is_cert_expired' do

    describe 'time argument not specified' do
      it 'returns true for expired certificate' do
        expired_cert = CertificateHelper.generate_cert(not_after: Time.now - 60)
        assert RubySaml::Utils.is_cert_expired(expired_cert)
      end

      it 'returns false for not-started certificate' do
        not_started_cert = CertificateHelper.generate_cert(not_before: Time.now + 60)
        refute RubySaml::Utils.is_cert_active(not_started_cert)
      end

      it 'returns false for active certificate' do
        valid_cert = CertificateHelper.generate_cert
        refute RubySaml::Utils.is_cert_expired(valid_cert)
      end

      it 'returns true for expired certificate string' do
        expired_cert_string = CertificateHelper.generate_cert(not_after: Time.now - 60).to_pem
        assert RubySaml::Utils.is_cert_expired(expired_cert_string)
      end

      it 'returns false for not-started certificate string' do
        not_started_cert_string = CertificateHelper.generate_cert(not_before: Time.now + 60).to_pem
        refute RubySaml::Utils.is_cert_active(not_started_cert_string)
      end

      it 'returns false for active certificate string' do
        valid_cert_string = CertificateHelper.generate_cert.to_pem
        refute RubySaml::Utils.is_cert_expired(valid_cert_string)
      end
    end

    describe 'time argument specified as Time' do
      let(:now) { Time.at(10000) }

      it 'returns true for expired certificate' do
        expired_cert = CertificateHelper.generate_cert(not_after: now - 60)
        assert RubySaml::Utils.is_cert_expired(expired_cert, now)
      end

      it 'returns false for not-started certificate' do
        not_started_cert = CertificateHelper.generate_cert(not_before: now + 60)
        refute RubySaml::Utils.is_cert_active(not_started_cert, now)
      end

      it 'returns false for active certificate' do
        valid_cert = CertificateHelper.generate_cert(not_before: now - 60, not_after: now + 60)
        refute RubySaml::Utils.is_cert_expired(valid_cert, now)
      end

      it 'returns true for expired certificate string' do
        expired_cert_string = CertificateHelper.generate_cert(not_after: now - 60).to_pem
        assert RubySaml::Utils.is_cert_expired(expired_cert_string, now)
      end

      it 'returns false for not-started certificate string' do
        not_started_cert_string = CertificateHelper.generate_cert(not_before: now + 60).to_pem
        refute RubySaml::Utils.is_cert_active(not_started_cert_string, now)
      end

      it 'returns false for active certificate string' do
        valid_cert_string = CertificateHelper.generate_cert(not_before: now - 60, not_after: now + 60).to_pem
        refute RubySaml::Utils.is_cert_expired(valid_cert_string, now)
      end
    end

    describe 'time argument specified as Integer' do
      let(:int) { 10000 }

      it 'returns true for expired certificate' do
        expired_cert = CertificateHelper.generate_cert(not_after: Time.at(int) - 60)
        assert RubySaml::Utils.is_cert_expired(expired_cert, int)
      end

      it 'returns false for not-started certificate' do
        not_started_cert = CertificateHelper.generate_cert(not_before: Time.at(int) + 60)
        refute RubySaml::Utils.is_cert_active(not_started_cert, int)
      end
    end
  end

  describe '.is_cert_active' do

    describe 'time argument not specified' do
      it 'returns true for active certificate' do
        valid_cert = CertificateHelper.generate_cert
        assert RubySaml::Utils.is_cert_active(valid_cert)
      end

      it 'returns false for not-started certificate' do
        not_started_cert = CertificateHelper.generate_cert(not_before: Time.now + 60)
        refute RubySaml::Utils.is_cert_active(not_started_cert)
      end

      it 'returns false for expired certificate' do
        expired_cert = CertificateHelper.generate_cert(not_after: Time.now - 60)
        refute RubySaml::Utils.is_cert_active(expired_cert)
      end

      it 'returns true for active certificate string' do
        valid_cert_string = CertificateHelper.generate_cert.to_pem
        assert RubySaml::Utils.is_cert_active(valid_cert_string)
      end

      it 'returns false for not-started certificate string' do
        not_started_cert_string = CertificateHelper.generate_cert(not_before: Time.now + 60).to_pem
        refute RubySaml::Utils.is_cert_active(not_started_cert_string)
      end

      it 'returns false for expired certificate string' do
        expired_cert_string = CertificateHelper.generate_cert(not_after: Time.now - 60).to_pem
        refute RubySaml::Utils.is_cert_active(expired_cert_string)
      end
    end

    describe 'time argument specified as Time' do
      let(:now) { Time.at(10000) }

      it 'returns true for active certificate' do
        valid_cert = CertificateHelper.generate_cert(not_before: now - 60, not_after: now + 60)
        assert RubySaml::Utils.is_cert_active(valid_cert, now)
      end

      it 'returns false for not-started certificate' do
        not_started_cert = CertificateHelper.generate_cert(not_before: now + 60)
        refute RubySaml::Utils.is_cert_active(not_started_cert, now)
      end

      it 'returns false for expired certificate' do
        expired_cert = CertificateHelper.generate_cert(not_after: now - 60)
        refute RubySaml::Utils.is_cert_active(expired_cert, now)
      end

      it 'returns true for active certificate string' do
        valid_cert_string = CertificateHelper.generate_cert(not_before: now - 60, not_after: now + 60).to_pem
        assert RubySaml::Utils.is_cert_active(valid_cert_string, now)
      end

      it 'returns false for not-started certificate string' do
        not_started_cert_string = CertificateHelper.generate_cert(not_before: now + 60).to_pem
        refute RubySaml::Utils.is_cert_active(not_started_cert_string, now)
      end

      it 'returns false for expired certificate string' do
        expired_cert_string = CertificateHelper.generate_cert(not_after: now - 60).to_pem
        refute RubySaml::Utils.is_cert_active(expired_cert_string, now)
      end
    end

    describe 'time argument specified as Integer' do
      let(:int) { 10000 }

      it 'returns true for active certificate' do
        valid_cert = CertificateHelper.generate_cert(not_before: Time.at(int) - 60, not_after: Time.at(int) + 60)
        assert RubySaml::Utils.is_cert_active(valid_cert, int)
      end

      it 'returns false for expired certificate' do
        expired_cert = CertificateHelper.generate_cert(not_after: Time.at(int) - 60)
        refute RubySaml::Utils.is_cert_active(expired_cert, int)
      end
    end
  end
end

require_relative 'test_helper'

require 'ruby_saml/settings'
require 'ruby_saml/validation_error'

class SettingsTest < Minitest::Test

  describe "Settings" do
    before do
      @settings = RubySaml::Settings.new
    end

    it "should provide getters and settings" do
      accessors = [
        :idp_entity_id, :idp_sso_target_url, :idp_sso_service_url, :idp_slo_target_url, :idp_slo_service_url, :valid_until,
        :idp_cert, :idp_cert_fingerprint, :idp_cert_fingerprint_algorithm, :idp_cert_multi,
        :idp_attribute_names, :issuer, :assertion_consumer_service_url, :single_logout_service_url,
        :sp_name_qualifier, :name_identifier_format, :name_identifier_value, :name_identifier_value_requested,
        :sessionindex, :attributes_index, :passive, :force_authn, :message_max_bytesize,
        :security, :certificate, :private_key, :certificate_new, :sp_cert_multi,
        :authn_context, :authn_context_comparison, :authn_context_decl_ref,
        :assertion_consumer_logout_service_url
      ]

      accessors.each do |accessor|
        value = Kernel.rand
        @settings.send("#{accessor}=".to_sym, value)
        assert_equal value, @settings.send(accessor)

        @settings.send("#{accessor}=".to_sym, nil)
        assert_nil @settings.send(accessor)
      end
    end

    it "should provide getters and settings for binding parameters" do
      accessors = [
        :protocol_binding,
        :assertion_consumer_service_binding,
        :single_logout_service_binding,
        :assertion_consumer_logout_service_binding
      ]

      accessors.each do |accessor|
        value = Kernel.rand.to_s
        @settings.send("#{accessor}=".to_sym, value)
        assert_equal value, @settings.send(accessor)

        @settings.send("#{accessor}=".to_sym, :redirect)
        assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.send(accessor)

        @settings.send("#{accessor}=".to_sym, :post)
        assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", @settings.send(accessor)

        @settings.send("#{accessor}=".to_sym, nil)
        assert_nil @settings.send(accessor)
      end
    end

    it "create settings from hash" do
      config = {
          :assertion_consumer_service_url => "http://app.muda.no/sso",
          :issuer => "http://muda.no",
          :sp_name_qualifier => "http://sso.muda.no",
          :idp_sso_service_url => "http://sso.muda.no/sso",
          :idp_sso_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          :idp_slo_service_url => "http://sso.muda.no/slo",
          :idp_slo_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          :idp_cert_fingerprint => "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
          :message_max_bytesize => 750000,
          :valid_until => '2029-04-16T03:35:08.277Z',
          :name_identifier_format => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          :attributes_index => 30,
          :passive => true,
          :protocol_binding => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      }
      @settings = RubySaml::Settings.new(config)

      config.each do |k,v|
        assert_equal v, @settings.send(k)
      end
    end

    it "configure attribute service attributes correctly" do
      @settings.attribute_consuming_service.configure do
        service_name "Test Service"
        add_attribute :name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name"
      end

      assert_equal @settings.attribute_consuming_service.configured?, true
      assert_equal @settings.attribute_consuming_service.name, "Test Service"
      assert_equal @settings.attribute_consuming_service.attributes, [{:name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name" }]
    end

    it "does not modify default security settings" do
      settings = RubySaml::Settings.new
      settings.security[:authn_requests_signed] = true
      settings.security[:digest_method] = RubySaml::XML::SHA512
      settings.security[:signature_method] = RubySaml::XML::RSA_SHA512

      new_settings = RubySaml::Settings.new
      assert_equal new_settings.security[:authn_requests_signed], false
      assert_equal new_settings.get_sp_digest_method, RubySaml::XML::SHA256
      assert_equal new_settings.get_sp_signature_method, RubySaml::XML::RSA_SHA256
    end

    it "overrides only provided security attributes passing a second parameter" do
      config = {
        :security => {
          :metadata_signed => true
        }
      }

      @default_attributes = RubySaml::Settings::DEFAULTS

      @settings = RubySaml::Settings.new(config, true)
      assert_equal @settings.security[:metadata_signed], true
      assert_equal @settings.security[:digest_method], @default_attributes[:security][:digest_method]
    end

    it "doesn't override only provided security attributes without passing a second parameter" do
      config = {
        :security => {
          :metadata_signed => true
        }
      }

      @default_attributes = RubySaml::Settings::DEFAULTS

      @settings = RubySaml::Settings.new(config)
      assert_equal @settings.security[:metadata_signed], true
      assert_nil @settings.security[:digest_method]
    end

    describe "#single_logout_service_url" do
      it "when single_logout_service_url is nil but assertion_consumer_logout_service_url returns its value" do
        @settings.single_logout_service_url = nil
        @settings.assertion_consumer_logout_service_url = "http://app.muda.no/sls"

        assert_equal "http://app.muda.no/sls", @settings.single_logout_service_url
      end
    end

    describe "#single_logout_service_binding" do
      it "when single_logout_service_binding is nil but assertion_consumer_logout_service_binding returns its value" do
        @settings.single_logout_service_binding = nil
        @settings.assertion_consumer_logout_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

        assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", @settings.single_logout_service_binding
      end
    end

    describe "#idp_sso_service_url" do
      it "when idp_sso_service_url is nil but idp_sso_target_url returns its value" do
        @settings.idp_sso_service_url = nil
        @settings.idp_sso_target_url = "https://idp.example.com/sso"

        assert_equal "https://idp.example.com/sso", @settings.idp_sso_service_url
      end
    end

    describe "#idp_slo_service_url" do
      it "when idp_slo_service_url is nil but idp_slo_target_url returns its value" do
        @settings.idp_slo_service_url = nil
        @settings.idp_slo_target_url = "https://idp.example.com/slo"

        assert_equal "https://idp.example.com/slo", @settings.idp_slo_service_url
      end
    end

    describe "#get_idp_cert" do
      it "returns nil when the cert is an empty string" do
        @settings.idp_cert = ""
        assert_nil @settings.get_idp_cert
      end

      it "returns nil when the cert is nil" do
        @settings.idp_cert = nil
        assert_nil @settings.get_idp_cert
      end

      it "returns the certificate when it is valid" do
        @settings.idp_cert = ruby_saml_cert_text
        assert @settings.get_idp_cert.kind_of? OpenSSL::X509::Certificate
      end

      it "raises when the certificate is not valid" do
        # formatted but invalid cert
        @settings.idp_cert = read_certificate("formatted_certificate")
        assert_raises(OpenSSL::X509::CertificateError) {
          @settings.get_idp_cert
        }
      end
    end

    describe "#get_idp_cert_multi" do
      it "returns nil when the value is empty" do
        @settings.idp_cert = {}
        assert_nil @settings.get_idp_cert_multi
      end

      it "returns nil when the idp_cert_multi is nil or empty" do
        @settings.idp_cert_multi = nil
        assert_nil @settings.get_idp_cert_multi
      end

      it "returns partial hash when contains some values" do
        empty_multi = {
          :signing => [],
          :encryption => []
        }

        @settings.idp_cert_multi = {
          :signing => []
        }
        assert_equal empty_multi, @settings.get_idp_cert_multi

        @settings.idp_cert_multi = {
          :encryption => []
        }
        assert_equal empty_multi, @settings.get_idp_cert_multi

        @settings.idp_cert_multi = {
          :signing => [],
          :encryption => []
        }
        assert_equal empty_multi, @settings.get_idp_cert_multi

        @settings.idp_cert_multi = {
          :yyy => [],
          :zzz => []
        }
        assert_equal empty_multi, @settings.get_idp_cert_multi
      end

      it "returns partial hash when contains some values with string keys" do
        empty_multi = {
          :signing => [],
          :encryption => []
        }

        @settings.idp_cert_multi = {
          "signing" => []
        }
        assert_equal empty_multi, @settings.get_idp_cert_multi

        @settings.idp_cert_multi = {
          "encryption" => []
        }
        assert_equal empty_multi, @settings.get_idp_cert_multi

        @settings.idp_cert_multi = {
          "signing" => [],
          "encryption" => []
        }
        assert_equal empty_multi, @settings.get_idp_cert_multi

        @settings.idp_cert_multi = {
          "yyy" => [],
          "zzz" => []
        }
        assert_equal empty_multi, @settings.get_idp_cert_multi
      end

      it "returns the hash with certificates when values were valid" do
        certificates = [ruby_saml_cert_text]
        @settings.idp_cert_multi = {
          :signing => certificates,
          :encryption => certificates,
        }

        assert @settings.get_idp_cert_multi.kind_of? Hash
        assert @settings.get_idp_cert_multi[:signing].kind_of? Array
        assert @settings.get_idp_cert_multi[:encryption].kind_of? Array
        assert @settings.get_idp_cert_multi[:signing][0].kind_of? OpenSSL::X509::Certificate
        assert @settings.get_idp_cert_multi[:encryption][0].kind_of? OpenSSL::X509::Certificate
      end

      it "returns the hash with certificates when values were valid and with string keys" do
        certificates = [ruby_saml_cert_text]
        @settings.idp_cert_multi = {
          "signing" => certificates,
          "encryption" => certificates,
        }

        assert @settings.get_idp_cert_multi.kind_of? Hash
        assert @settings.get_idp_cert_multi[:signing].kind_of? Array
        assert @settings.get_idp_cert_multi[:encryption].kind_of? Array
        assert @settings.get_idp_cert_multi[:signing][0].kind_of? OpenSSL::X509::Certificate
        assert @settings.get_idp_cert_multi[:encryption][0].kind_of? OpenSSL::X509::Certificate
      end

      it "raises when there is a cert in idp_cert_multi not valid" do
        certificate = read_certificate("formatted_certificate")

        @settings.idp_cert_multi = {
          :signing => [],
          :encryption => []
        }
        @settings.idp_cert_multi[:signing].push(certificate)
        @settings.idp_cert_multi[:encryption].push(certificate)

        assert_raises(OpenSSL::X509::CertificateError) {
          @settings.get_idp_cert_multi
        }
      end
    end

    describe "#get_sp_cert" do
      it "returns nil when the cert is an empty string" do
        @settings.certificate = ''

        assert_nil @settings.get_sp_cert
      end

      it "returns nil when the cert is nil" do
        @settings.certificate = nil

        assert_nil @settings.get_sp_cert
      end

      it "returns the certificate when it is valid" do
        @settings.certificate = ruby_saml_cert_text

        assert @settings.get_sp_cert.kind_of? OpenSSL::X509::Certificate
      end

      it "raises when the certificate is not valid" do
        # formatted but invalid cert
        @settings.certificate = read_certificate("formatted_certificate")

        assert_raises(OpenSSL::X509::CertificateError) { @settings.get_sp_cert }
      end

      it "raises an error if SP certificate expired and check_sp_cert_expiration enabled" do
        @settings.certificate = ruby_saml_cert_text
        @settings.security[:check_sp_cert_expiration] = true

        assert_raises(RubySaml::ValidationError) { @settings.get_sp_cert }
      end

      each_key_algorithm do |sp_cert_algo|
        it "allows a certificate with a #{sp_cert_algo.upcase} private key" do
          @settings.certificate, _= CertificateHelper.generate_cert(sp_cert_algo).to_pem

          assert @settings.get_sp_cert.kind_of? OpenSSL::X509::Certificate
        end
      end
    end

    describe "#get_sp_cert_new" do
      it "returns nil when the cert is an empty string" do
        @settings.certificate_new = ''

        assert_nil @settings.get_sp_cert_new
      end

      it "returns nil when the cert is nil" do
        @settings.certificate_new = nil

        assert_nil @settings.get_sp_cert_new
      end

      it "returns the certificate when it is valid" do
        @settings.certificate_new = ruby_saml_cert_text

        assert @settings.get_sp_cert_new.kind_of? OpenSSL::X509::Certificate
      end

      it "raises when the certificate is formatted but invalid" do
        @settings.certificate_new = read_certificate("formatted_certificate")

        assert_raises(OpenSSL::X509::CertificateError) { @settings.get_sp_cert_new }
      end

      each_key_algorithm do |sp_cert_algo|
        it "allows a certificate with a #{sp_cert_algo.upcase} private key" do
          @settings.certificate_new = CertificateHelper.generate_cert(sp_cert_algo).to_pem

          assert @settings.get_sp_cert_new.kind_of? OpenSSL::X509::Certificate
        end
      end
    end

    describe "#get_sp_key" do
      it "returns nil when the private key is an empty string" do
        @settings.private_key = ''

        assert_nil @settings.get_sp_key
      end

      it "returns nil when the private key is nil" do
        @settings.private_key = nil

        assert_nil @settings.get_sp_key
      end

      it "returns the private key when it is valid" do
        @settings.private_key = ruby_saml_key_text

        assert @settings.get_sp_key.kind_of? OpenSSL::PKey::RSA
      end

      it "raises when the private key is formatted but invalid" do
        @settings.private_key = read_certificate("formatted_rsa_private_key")

        assert_raises(OpenSSL::PKey::RSAError) { @settings.get_sp_key }
      end

      each_key_algorithm do |sp_cert_algo|
        it "allows a #{sp_cert_algo.upcase} private key" do
          @settings.private_key = CertificateHelper.generate_private_key(sp_cert_algo).to_pem

          assert @settings.get_sp_key.kind_of? expected_key_class(sp_cert_algo)
        end
      end
    end

    describe "#get_fingerprint" do
      it "get the fingerprint value when cert and fingerprint in settings are nil" do
        @settings.idp_cert_fingerprint = nil
        @settings.idp_cert = nil
        fingerprint = @settings.get_fingerprint
        assert_nil fingerprint
      end

      it "get the fingerprint value when there is a cert at the settings" do
        @settings.idp_cert_fingerprint = nil
        @settings.idp_cert = ruby_saml_cert_text
        fingerprint = @settings.get_fingerprint
        assert fingerprint.downcase == ruby_saml_cert_fingerprint.downcase
      end

      it "get the fingerprint value when there is a fingerprint at the settings" do
        @settings.idp_cert_fingerprint = ruby_saml_cert_fingerprint
        @settings.idp_cert = nil
        fingerprint = @settings.get_fingerprint
        assert fingerprint.downcase == ruby_saml_cert_fingerprint.downcase
      end

      it "get the fingerprint value when there are cert and fingerprint at the settings" do
        @settings.idp_cert_fingerprint = ruby_saml_cert_fingerprint
        @settings.idp_cert = ruby_saml_cert_text
        fingerprint = @settings.get_fingerprint
        assert fingerprint.downcase == ruby_saml_cert_fingerprint.downcase
      end
    end

    describe "#get_sp_certs (base cases)" do
      let(:cert_text1) { ruby_saml_cert_text }
      let(:cert_text2) { ruby_saml_cert2.to_pem }
      let(:cert_text3) { CertificateHelper.generate_cert.to_pem }
      let(:key_text1)  { ruby_saml_key_text }
      let(:key_text2)  { CertificateHelper.generate_private_key.to_pem }

      it "returns certs for single case" do
        @settings.certificate = cert_text1
        @settings.private_key = key_text1

        actual = @settings.get_sp_certs
        expected = [[cert_text1, key_text1]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected, actual[:signing].map {|ary| ary.map(&:to_pem) }
        assert_equal expected, actual[:encryption].map {|ary| ary.map(&:to_pem) }
      end

      it "returns certs for single case with new cert" do
        @settings.certificate = cert_text1
        @settings.certificate_new = cert_text2
        @settings.private_key = key_text1

        actual = @settings.get_sp_certs
        expected = [[cert_text1, key_text1], [cert_text2, key_text1]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected, actual[:signing].map {|ary| ary.map(&:to_pem) }
        assert_equal expected, actual[:encryption].map {|ary| ary.map(&:to_pem) }
      end

      it "returns certs for multi case" do
        @settings.sp_cert_multi = {
          signing: [{ certificate: cert_text1, private_key: key_text1 },
                    { certificate: cert_text2, private_key: key_text1 }],
          encryption: [{ certificate: cert_text2, private_key: key_text1 },
                       { certificate: cert_text3, private_key: key_text2 }]
        }

        actual = @settings.get_sp_certs
        expected_signing = [[cert_text1, key_text1], [cert_text2, key_text1]]
        expected_encryption = [[cert_text2, key_text1], [cert_text3, key_text2]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected_signing, actual[:signing].map { |ary| ary.map(&:to_pem) }
        assert_equal expected_encryption, actual[:encryption].map { |ary| ary.map(&:to_pem) }
      end

      # TODO: :encryption should validate only RSA keys are used
      each_key_algorithm do |sp_cert_algo|
        it "sp_cert_multi allows #{sp_cert_algo.upcase} certs and private keys" do
          @cert1, @pkey = CertificateHelper.generate_pair(sp_cert_algo)
          @cert2 = CertificateHelper.generate_cert(@pkey)
          @settings.sp_cert_multi = {
            signing: [{ certificate: @cert1.to_pem, private_key: @pkey.to_pem },
                      { certificate: @cert2.to_pem, private_key: @pkey.to_pem },
                      { certificate: cert_text1, private_key: key_text1 }],
            encryption: [{ certificate: @cert1.to_pem, private_key: @pkey.to_pem },
                         { certificate: @cert2.to_pem, private_key: @pkey.to_pem },
                         { certificate: cert_text2, private_key: key_text2 }]
          }

          actual = @settings.get_sp_certs
          expected_signing = @settings.sp_cert_multi[:signing].map { |pair| pair.values }
          expected_encryption = @settings.sp_cert_multi[:encryption].map { |pair| pair.values }
          assert_equal [:signing, :encryption], actual.keys
          assert_equal expected_signing, actual[:signing].map { |ary| ary.map(&:to_pem) }
          assert_equal expected_encryption, actual[:encryption].map { |ary| ary.map(&:to_pem) }
        end
      end

      it 'handles OpenSSL::X509::Certificate objects for single case' do
        @settings.certificate = OpenSSL::X509::Certificate.new(cert_text1)
        @settings.private_key = key_text1

        actual = @settings.get_sp_certs
        expected = [[cert_text1, key_text1]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected, actual[:signing].map { |ary| ary.map(&:to_pem) }
        assert_equal expected, actual[:encryption].map { |ary| ary.map(&:to_pem) }
      end

      it 'handles OpenSSL::X509::Certificate objects for single case with new cert' do
        @settings.certificate = cert_text1
        @settings.certificate_new = OpenSSL::X509::Certificate.new(cert_text2)
        @settings.private_key = key_text1

        actual = @settings.get_sp_certs
        expected = [[cert_text1, key_text1], [cert_text2, key_text1]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected, actual[:signing].map { |ary| ary.map(&:to_pem) }
        assert_equal expected, actual[:encryption].map { |ary| ary.map(&:to_pem) }
      end

      it 'handles OpenSSL::X509::Certificate objects for multi case' do
        x509_certificate1 = OpenSSL::X509::Certificate.new(cert_text1)
        x509_certificate2 = OpenSSL::X509::Certificate.new(cert_text2)
        @settings.sp_cert_multi = {
          signing: [{ certificate: x509_certificate1, private_key: key_text1 },
                    { certificate: cert_text2, private_key: key_text1 }],
          encryption: [{ certificate: x509_certificate2, private_key: key_text1 },
                       { certificate: cert_text3, private_key: key_text2 }]
        }

        actual = @settings.get_sp_certs
        expected_signing = [[cert_text1, key_text1], [cert_text2, key_text1]]
        expected_encryption = [[cert_text2, key_text1], [cert_text3, key_text2]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected_signing, actual[:signing].map { |ary| ary.map(&:to_pem) }
        assert_equal expected_encryption, actual[:encryption].map { |ary| ary.map(&:to_pem) }
      end

      it 'handles OpenSSL::PKey::PKey objects for single case' do
        @settings.certificate = cert_text1
        @settings.private_key = OpenSSL::PKey::RSA.new(key_text1)

        actual = @settings.get_sp_certs
        expected = [[cert_text1, key_text1]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected, actual[:signing].map { |ary| ary.map(&:to_pem) }
        assert_equal expected, actual[:encryption].map { |ary| ary.map(&:to_pem) }
      end

      it 'handles OpenSSL::PKey::PKey objects for multi case' do
        pkey2 = OpenSSL::PKey::RSA.new(key_text2)
        pkey3 = CertificateHelper.generate_private_key(:dsa)
        pkey4 = CertificateHelper.generate_private_key(:ecdsa)
        @settings.sp_cert_multi = {
          signing: [{ certificate: cert_text1, private_key: pkey3 },
                    { certificate: cert_text2, private_key: pkey4 }],
          encryption: [{ certificate: cert_text2, private_key: key_text1 },
                       { certificate: cert_text3, private_key: pkey2 }]
        }

        actual = @settings.get_sp_certs
        expected_signing = [[cert_text1, pkey3.to_pem], [cert_text2, pkey4.to_pem]]
        expected_encryption = [[cert_text2, key_text1], [cert_text3, key_text2]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected_signing, actual[:signing].map { |ary| ary.map(&:to_pem) }
        assert_equal expected_encryption, actual[:encryption].map { |ary| ary.map(&:to_pem) }
      end

      it "sp_cert_multi allows sending only signing" do
        @settings.sp_cert_multi = {
          signing: [{ certificate: cert_text1, private_key: key_text1 },
                    { certificate: cert_text2, private_key: key_text1 }]
        }

        actual = @settings.get_sp_certs
        expected_signing = [[cert_text1, key_text1], [cert_text2, key_text1]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected_signing, actual[:signing].map {|ary| ary.map(&:to_pem) }
        assert_equal [], actual[:encryption]
      end

      it "raises error when sp_cert_multi is not a Hash" do
        @settings.sp_cert_multi = 'invalid_type'

        error_message = 'sp_cert_multi must be a Hash'
        assert_raises ArgumentError, error_message do
          @settings.get_sp_certs
        end
      end

      it "raises error when sp_cert_multi does not contain an Array of Hashes" do
        @settings.sp_cert_multi = { signing: 'invalid_type' }

        error_message = 'sp_cert_multi :signing node must be an Array of Hashes'
        assert_raises ArgumentError, error_message do
          @settings.get_sp_certs
        end
      end

      it "raises error when sp_cert_multi inner node missing :certificate" do
        @settings.sp_cert_multi = { signing: [{ private_key: key_text1 }] }

        error_message = 'sp_cert_multi :signing node Hashes must specify keys :certificate and :private_key'
        assert_raises ArgumentError, error_message do
          @settings.get_sp_certs
        end
      end

      it "raises error when sp_cert_multi inner node missing :private_key" do
        @settings.sp_cert_multi = { signing: [{ certificate: cert_text1 }] }

        error_message = 'sp_cert_multi :signing node Hashes must specify keys :certificate and :private_key'
        assert_raises ArgumentError, error_message do
          @settings.get_sp_certs
        end
      end

      it "handles sp_cert_multi with string keys" do
        @settings.sp_cert_multi = {
          'signing' => [{ 'certificate' => cert_text1, 'private_key' => key_text1 }],
          'encryption' => [{ 'certificate' => cert_text2, 'private_key' => key_text1 }]
        }

        actual = @settings.get_sp_certs
        expected_signing = [[cert_text1, key_text1]]
        expected_encryption = [[cert_text2, key_text1]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected_signing, actual[:signing].map {|ary| ary.map(&:to_pem) }
        assert_equal expected_encryption, actual[:encryption].map {|ary| ary.map(&:to_pem) }
      end

      it "handles sp_cert_multi with alternate inner keys :cert and :key" do
        @settings.sp_cert_multi = {
          signing: [{ cert: cert_text1, key: key_text1 }],
          encryption: [{ 'cert' => cert_text2, 'key' => key_text1 }]
        }

        actual = @settings.get_sp_certs
        expected_signing = [[cert_text1, key_text1]]
        expected_encryption = [[cert_text2, key_text1]]
        assert_equal [:signing, :encryption], actual.keys
        assert_equal expected_signing, actual[:signing].map {|ary| ary.map(&:to_pem) }
        assert_equal expected_encryption, actual[:encryption].map {|ary| ary.map(&:to_pem) }
      end

      it "raises error when both sp_cert_multi and certificate are specified" do
        @settings.sp_cert_multi = { signing: [{ certificate: cert_text1, private_key: key_text1 }] }
        @settings.certificate = cert_text1

        error_message = 'Cannot specify both sp_cert_multi and certificate, certificate_new, private_key parameters'
        assert_raises ArgumentError, error_message do
          @settings.get_sp_certs
        end
      end

      it "raises error when both sp_cert_multi and certificate_new are specified" do
        @settings.sp_cert_multi = { signing: [{ certificate: cert_text1, private_key: key_text1 }] }
        @settings.certificate_new = cert_text2

        error_message = 'Cannot specify both sp_cert_multi and certificate, certificate_new, private_key parameters'
        assert_raises ArgumentError, error_message do
          @settings.get_sp_certs
        end
      end

      it "raises error when both sp_cert_multi and private_key are specified" do
        @settings.sp_cert_multi = { signing: [{ certificate: cert_text1, private_key: key_text1 }] }
        @settings.private_key = key_text1

        error_message = 'Cannot specify both sp_cert_multi and certificate, certificate_new, private_key parameters'
        assert_raises ArgumentError, error_message do
          @settings.get_sp_certs
        end
      end
    end

    describe "#get_sp_certs" do
      let(:valid_pair) { CertificateHelper.generate_pem_hash }
      let(:early_pair) { CertificateHelper.generate_pem_hash(not_before: Time.now + 60) }
      let(:expired_pair) { CertificateHelper.generate_pem_hash(not_after: Time.now - 60) }

      it "returns all certs when check_sp_cert_expiration is false" do
        @settings.security = { check_sp_cert_expiration: false }
        @settings.sp_cert_multi = { signing: [valid_pair, expired_pair], encryption: [valid_pair, early_pair] }

        actual = @settings.get_sp_certs
        expected_signing = [valid_pair, expired_pair].map(&:values)
        expected_encryption = [valid_pair, early_pair].map(&:values)
        assert_equal expected_signing, actual[:signing].map {|ary| ary.map(&:to_pem) }
        assert_equal expected_encryption, actual[:encryption].map {|ary| ary.map(&:to_pem) }
      end

      it "returns only active certs when check_sp_cert_expiration is true" do
        @settings.security = { check_sp_cert_expiration: true }
        @settings.sp_cert_multi = { signing: [valid_pair, expired_pair], encryption: [valid_pair, early_pair] }

        actual = @settings.get_sp_certs
        expected_active = [valid_pair].map(&:values)
        assert_equal expected_active, actual[:signing].map {|ary| ary.map(&:to_pem) }
        assert_equal expected_active, actual[:encryption].map {|ary| ary.map(&:to_pem) }
      end

      it "raises error when all certificates are expired in signing and check_sp_cert_expiration is true" do
        @settings.security = { check_sp_cert_expiration: true }
        @settings.sp_cert_multi = { signing: [expired_pair], encryption: [valid_pair] }

        assert_raises RubySaml::ValidationError do
          @settings.get_sp_certs
        end
      end

      it "raises error when all certificates are expired in encryption and check_sp_cert_expiration is true" do
        @settings.security = { check_sp_cert_expiration: true }
        @settings.sp_cert_multi = { signing: [valid_pair], encryption: [expired_pair] }

        assert_raises RubySaml::ValidationError do
          @settings.get_sp_certs
        end
      end

      it "returns empty arrays for signing and encryption if no pairs are present" do
        @settings.sp_cert_multi = { signing: [], encryption: [] }

        actual = @settings.get_sp_certs
        assert_empty actual[:signing]
        assert_empty actual[:encryption]
      end
    end

    describe "#get_sp_signing_pair and #get_sp_signing_key" do
      let(:valid_pair) { CertificateHelper.generate_pem_hash }
      let(:early_pair) { CertificateHelper.generate_pem_hash(not_before: Time.now + 60) }
      let(:expired)  { CertificateHelper.generate_pem_hash(not_after: Time.now - 60) }

      it "returns nil when no signing pairs are present" do
        @settings.sp_cert_multi = { signing: [] }

        assert_nil @settings.get_sp_signing_pair
        assert_nil @settings.get_sp_signing_key
      end

      it "returns the first pair if check_sp_cert_expiration is false" do
        @settings.security = { check_sp_cert_expiration: false }
        @settings.sp_cert_multi = { signing: [early_pair, expired, valid_pair] }

        assert_equal early_pair.values, @settings.get_sp_signing_pair.map(&:to_pem)
        assert_equal early_pair[:private_key], @settings.get_sp_signing_key.to_pem
      end

      it "returns the first active pair when check_sp_cert_expiration is true" do
        @settings.security = { check_sp_cert_expiration: true }
        @settings.sp_cert_multi = { signing: [early_pair, expired, valid_pair] }

        assert_equal valid_pair.values, @settings.get_sp_signing_pair.map(&:to_pem)
        assert_equal valid_pair[:private_key], @settings.get_sp_signing_key.to_pem
      end

      it "raises error when all certificates are expired and check_sp_cert_expiration is true" do
        @settings.security = { check_sp_cert_expiration: true }
        @settings.sp_cert_multi = { signing: [early_pair, expired] }

        assert_raises RubySaml::ValidationError do
          @settings.get_sp_signing_pair
        end

        assert_raises RubySaml::ValidationError do
          @settings.get_sp_signing_key
        end
      end
    end

    describe "#get_sp_decryption_keys" do
      let(:valid_pair) { CertificateHelper.generate_pem_hash }
      let(:early_pair) { CertificateHelper.generate_pem_hash(not_before: Time.now + 60) }
      let(:expired_pair) { CertificateHelper.generate_pem_hash(not_after: Time.now - 60) }

      it "returns an empty array when no decryption pairs are present" do
        @settings.sp_cert_multi = { encryption: [] }

        assert_empty @settings.get_sp_decryption_keys
      end

      it "returns all keys when check_sp_cert_expiration is false" do
        @settings.security = { check_sp_cert_expiration: false }
        @settings.sp_cert_multi = { encryption: [early_pair, expired_pair, valid_pair] }

        expected_keys = [early_pair, expired_pair, valid_pair].map { |pair| pair[:private_key] }
        actual_keys = @settings.get_sp_decryption_keys.map(&:to_pem)
        assert_equal expected_keys, actual_keys
      end

      it "returns only keys of active certificates when check_sp_cert_expiration is true" do
        @settings.security = { check_sp_cert_expiration: true }
        @settings.sp_cert_multi = { encryption: [early_pair, expired_pair, valid_pair] }

        expected_keys = [valid_pair[:private_key]]
        actual_keys = @settings.get_sp_decryption_keys.map(&:to_pem)
        assert_equal expected_keys, actual_keys
      end

      it "raises error when all certificates are expired and check_sp_cert_expiration is true" do
        @settings.security = { check_sp_cert_expiration: true }
        @settings.sp_cert_multi = { encryption: [early_pair, expired_pair] }

        assert_raises RubySaml::ValidationError do
          @settings.get_sp_decryption_keys
        end
      end

      it "removes duplicates" do
        @settings.sp_cert_multi = { encryption: [early_pair, valid_pair, early_pair, valid_pair] }

        expected_keys = [early_pair, valid_pair].map { |pair| pair[:private_key] }
        actual_keys = @settings.get_sp_decryption_keys.map(&:to_pem)

        assert_equal expected_keys, actual_keys
      end
    end

    describe '#get_sp_signature_method' do
      describe 'assumes RSA when sp_cert is nil' do
        before do
          @settings.certificate = nil
          @settings.private_key = nil
        end

        it 'uses RSA SHA256 by default' do
          assert_equal RubySaml::XML::SHA256, @settings.get_sp_digest_method
        end

        it 'can be set as a full string' do
          @settings.security[:signature_method] = RubySaml::XML::DSA_SHA1

          assert_equal RubySaml::XML::DSA_SHA1, @settings.get_sp_signature_method
        end

        it 'can be set as a short string' do
          @settings.security[:signature_method] = 'EC SHA512'

          assert_equal RubySaml::XML::ECDSA_SHA512, @settings.get_sp_signature_method
        end

        it 'can be set as a symbol' do
          @settings.security[:signature_method] = :ecdsa_sha384

          assert_equal RubySaml::XML::ECDSA_SHA384, @settings.get_sp_signature_method
        end

        it 'can be set as a hash algo full string' do
          @settings.security[:signature_method] = RubySaml::XML::SHA1

          assert_equal RubySaml::XML::RSA_SHA1, @settings.get_sp_signature_method
        end

        it 'can be set as a hash algo short string' do
          @settings.security[:signature_method] = 'SHA512'

          assert_equal RubySaml::XML::RSA_SHA512, @settings.get_sp_signature_method
        end

        it 'can be set as a hash algo symbol' do
          @settings.security[:signature_method] = :sha384

          assert_equal RubySaml::XML::RSA_SHA384, @settings.get_sp_signature_method
        end

        it 'raises error when digest method is invalid' do
          @settings.security[:signature_method] = 'RSA_SHA999'

          assert_raises(ArgumentError, 'Unsupported signature method: RSA_SHA999') do
            @settings.get_sp_signature_method
          end
        end
      end

      each_key_algorithm do |sp_key_algo|
        describe 'when sp_cert is set' do
          before { @settings.certificate, @settings.private_key = CertificateHelper.generate_pem_array(sp_key_algo) }

          it "uses #{sp_key_algo} SHA256 by default" do
            assert_equal signature_method(sp_key_algo, :sha256), @settings.get_sp_signature_method
          end

          it 'can be set as a full string' do
            @settings.security[:signature_method] = RubySaml::XML::SHA1

            assert_equal signature_method(sp_key_algo, :sha1), @settings.get_sp_signature_method
          end

          it 'can be set as a short string' do
            @settings.security[:signature_method] = 'EC SHA512'

            if sp_key_algo == :dsa
              assert_raises(ArgumentError, 'Unsupported signature method for DSA key: SHA512') { @settings.get_sp_signature_method }
            else
              assert_equal signature_method(sp_key_algo, :sha512), @settings.get_sp_signature_method
            end
          end

          it 'can be set as a symbol' do
            @settings.security[:signature_method] = :ecdsa_sha384

            if sp_key_algo == :dsa
              assert_raises(ArgumentError, 'Unsupported signature method for DSA key: SHA512') { @settings.get_sp_signature_method }
            else
              assert_equal signature_method(sp_key_algo, :sha384), @settings.get_sp_signature_method
            end
          end

          it 'can be set as a hash algo full string' do
            @settings.security[:signature_method] = RubySaml::XML::DSA_SHA1

            assert_equal signature_method(sp_key_algo, :sha1), @settings.get_sp_signature_method
          end

          it 'can be set as a hash algo short string' do
            @settings.security[:signature_method] = 'SHA512'

            if sp_key_algo == :dsa
              assert_raises(ArgumentError, 'Unsupported signature method for DSA key: SHA512') { @settings.get_sp_signature_method }
            else
              assert_equal signature_method(sp_key_algo, :sha512), @settings.get_sp_signature_method
            end
          end

          it 'can be set as a hash algo symbol' do
            @settings.security[:signature_method] = :sha1

            assert_equal signature_method(sp_key_algo, :sha1), @settings.get_sp_signature_method
          end

          it 'raises error when digest method is invalid' do
            @settings.security[:signature_method] = 'RSA_SHA999'

            assert_raises(ArgumentError, "Unsupported signature method for #{sp_key_algo.to_s.upcase} key: RSA_SHA999") do
              @settings.get_sp_signature_method
            end
          end
        end
      end
    end

    describe '#get_sp_digest_method' do
      it 'uses SHA256 by default' do
        assert_equal RubySaml::XML::SHA256, @settings.get_sp_digest_method
      end

      it 'can be set as full string' do
        @settings.security[:digest_method] = RubySaml::XML::SHA224

        assert_equal RubySaml::XML::SHA224, @settings.get_sp_digest_method
      end

      it 'can be set as short string' do
        @settings.security[:digest_method] = 'SHA512'

        assert_equal RubySaml::XML::SHA512, @settings.get_sp_digest_method
      end

      it 'can be set as symbol' do
        @settings.security[:digest_method] = :sha384

        assert_equal RubySaml::XML::SHA384, @settings.get_sp_digest_method
      end

      it 'raises error when digest method is invalid' do
        @settings.security[:digest_method] = 'SHA999'

        assert_raises(ArgumentError, 'Unsupported digest method: SHA999') do
          @settings.get_sp_digest_method
        end
      end
    end

    describe '#cert?' do
      it 'returns true for a valid OpenSSL::X509::Certificate object' do
        cert = CertificateHelper.generate_cert
        assert @settings.send(:cert?, cert)
      end

      it 'returns true for a non-empty certificate string' do
        cert_string = '-----BEGIN CERTIFICATE-----\nVALID_CERTIFICATE\n-----END CERTIFICATE-----'
        assert @settings.send(:cert?, cert_string)
      end

      it 'returns false for an empty certificate string' do
        cert_string = ''
        refute @settings.send(:cert?, cert_string)
      end

      it 'returns false for nil' do
        cert = nil
        refute @settings.send(:cert?, cert)
      end
    end

    describe '#private_key?' do
      it 'returns true for a valid OpenSSL::PKey::PKey object' do
        private_key = CertificateHelper.generate_private_key
        assert @settings.send(:private_key?, private_key)
      end

      it 'returns true for a non-empty private key string' do
        private_key_string = '-----BEGIN PRIVATE KEY-----\nVALID_PRIVATE_KEY\n-----END PRIVATE KEY-----'
        assert @settings.send(:private_key?, private_key_string)
      end

      it 'returns false for an empty private key string' do
        private_key_string = ''
        refute @settings.send(:private_key?, private_key_string)
      end

      it 'returns false for nil' do
        private_key = nil
        refute @settings.send(:private_key?, private_key)
      end
    end
  end
end

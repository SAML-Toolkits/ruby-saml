require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class SettingsTest < Minitest::Test

  describe "Settings" do
    before do
      @settings = OneLogin::RubySaml::Settings.new
    end
    it "should provide getters and settings" do
      accessors = [
        :assertion_consumer_service_url, :issuer, :sp_entity_id, :sp_name_qualifier,
        :idp_sso_target_url, :idp_cert_fingerprint, :name_identifier_format,
        :idp_slo_target_url, :name_identifier_value, :name_identifier_value_requested,
        :sessionindex, :assertion_consumer_logout_service_url,
        :passive, :force_authn, :protocol_binding, :single_logout_service_url, :single_logout_service_binding
      ]

      accessors.each do |accessor|
        value = Kernel.rand
        @settings.send("#{accessor}=".to_sym, value)
        assert_equal value, @settings.send(accessor)
      end
    end

    it "create settings from hash" do

      config = {
          :assertion_consumer_service_url => "http://app.muda.no/sso",
          :issuer => "http://muda.no",
          :sp_name_qualifier => "http://sso.muda.no",
          :idp_sso_target_url => "http://sso.muda.no/sso",
          :idp_slo_target_url => "http://sso.muda.no/slo",
          :idp_cert_fingerprint => "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
          :name_identifier_format => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          :passive => true,
          :protocol_binding => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      }
      @settings = OneLogin::RubySaml::Settings.new(config)

      config.each do |k,v|
        assert_equal v, @settings.send(k)
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

    describe "#get_sp_cert" do
      it "returns nil when the cert is an empty string" do
        @settings.certificate = ""
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
        assert_raises(OpenSSL::X509::CertificateError) {
          @settings.get_sp_cert
        }
      end
    end

    describe "#get_sp_key" do
      it "returns nil when the private key is an empty string" do
        @settings.private_key = ""
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

      it "raises when the private key is not valid" do
        # formatted but invalid rsa private key
        @settings.private_key = read_certificate("formatted_rsa_private_key")
        assert_raises(OpenSSL::PKey::RSAError) {
          @settings.get_sp_key
        }
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

  end

end

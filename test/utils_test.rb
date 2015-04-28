require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RubySamlTest < Minitest::Test

  describe "#format_cert" do
    it "return empty string when the cert is an empty string" do
      cert = ""
      assert_equal cert, OneLogin::RubySaml::Utils.format_cert(cert, true)
      assert_equal cert, OneLogin::RubySaml::Utils.format_cert(cert, false)
    end

    it "return formatted cert with head from cert with head" do
      cert = ruby_saml_cert_text
      formatted_cert = OneLogin::RubySaml::Utils.format_cert(cert, true)
      assert cert.include? "-----BEGIN CERTIFICATE-----"
      assert cert.include? "-----END CERTIFICATE-----"
      assert_equal cert, formatted_cert
      assert formatted_cert.include? "-----BEGIN CERTIFICATE-----"
      assert formatted_cert.include? "-----END CERTIFICATE-----"
    end

    it "return formatted cert with head from cert without head" do
      cert = ruby_saml_cert_text
      cert = cert.delete("\n").delete("\r").delete("\x0D")
      cert = cert.gsub('-----BEGIN CERTIFICATE-----', '')
      cert = cert.gsub('-----END CERTIFICATE-----', '')
      formatted_cert = OneLogin::RubySaml::Utils.format_cert(cert, true)
      assert !(cert.include? "-----BEGIN CERTIFICATE-----")
      assert !(cert.include? "-----END CERTIFICATE-----")
      refute_equal cert, formatted_cert
      assert formatted_cert.include? "-----BEGIN CERTIFICATE-----"
      assert formatted_cert.include? "-----END CERTIFICATE-----"
    end

    it "return formatted cert without head from cert with head" do
      cert = ruby_saml_cert_text
      formatted_cert = OneLogin::RubySaml::Utils.format_cert(cert, false)
      assert cert.include? "-----BEGIN CERTIFICATE-----"
      assert cert.include? "-----END CERTIFICATE-----"
      refute_equal cert, formatted_cert
      assert !(formatted_cert.include? "-----BEGIN CERTIFICATE-----")
      assert !(formatted_cert.include? "-----END CERTIFICATE-----")
      assert cert.include? formatted_cert
    end

    it "return formatted cert without head from cert without head" do
      cert = ruby_saml_cert_text
      cert = cert.delete("\n").delete("\r").delete("\x0D")
      cert = cert.gsub('-----BEGIN CERTIFICATE-----', '')
      cert = cert.gsub('-----END CERTIFICATE-----', '')
      formatted_cert = OneLogin::RubySaml::Utils.format_cert(cert, false)
      assert !(cert.include? "-----BEGIN CERTIFICATE-----")
      assert !(cert.include? "-----END CERTIFICATE-----")
      refute_equal cert, formatted_cert
      assert !(formatted_cert.include? "-----BEGIN CERTIFICATE-----")
      assert !(formatted_cert.include? "-----END CERTIFICATE-----")
    end
  end


  describe "#format_private_key" do
    it "return empty string when the RSA private_key is an empty string" do
      private_key = ""
      assert_equal private_key, OneLogin::RubySaml::Utils.format_private_key(private_key, true)
      assert_equal private_key, OneLogin::RubySaml::Utils.format_private_key(private_key, false)
    end

    it "return formatted RSA private_key with head from RSA private_key with head" do
      private_key = ruby_saml_key_text
      formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key, true)
      assert private_key.include? "-----BEGIN RSA PRIVATE KEY-----"
      assert private_key.include? "-----END RSA PRIVATE KEY-----"
      assert_equal private_key, formatted_private_key
      assert formatted_private_key.include? "-----BEGIN RSA PRIVATE KEY-----"
      assert formatted_private_key.include? "-----END RSA PRIVATE KEY-----"
    end

    it "return formatted RSA private_key with head from RSA private_key without head" do
      private_key = ruby_saml_key_text
      private_key = private_key.delete("\n\r\x0D")
      private_key = private_key.gsub('-----BEGIN RSA PRIVATE KEY-----', '')
      private_key = private_key.gsub('-----END RSA PRIVATE KEY-----', '')
      formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key, true)
      assert !(private_key.include? "-----BEGIN RSA PRIVATE KEY-----")
      assert !(private_key.include? "-----END RSA PRIVATE KEY-----")
      refute_equal private_key, formatted_private_key
      assert formatted_private_key.include? "-----BEGIN RSA PRIVATE KEY-----"
      assert formatted_private_key.include? "-----END RSA PRIVATE KEY-----"
    end

    it "return formatted RSA private_key without head from RSA private_key with head" do
      private_key = ruby_saml_key_text
      formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key, false)
      assert private_key.include? "-----BEGIN RSA PRIVATE KEY-----"
      assert private_key.include? "-----END RSA PRIVATE KEY-----"
      refute_equal private_key, formatted_private_key
      assert !(formatted_private_key.include? "-----BEGIN RSA PRIVATE KEY-----")
      assert !(formatted_private_key.include? "-----END RSA PRIVATE KEY-----")
      assert private_key.include? formatted_private_key
    end

    it "return formatted RSA private_key without head from RSA private_key without head" do
      private_key = ruby_saml_key_text
      private_key = private_key.delete("\n\r\x0D")
      private_key = private_key.gsub('-----BEGIN RSA PRIVATE KEY-----', '')
      private_key = private_key.gsub('-----END RSA PRIVATE KEY-----', '')
      formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key, false)
      assert !(private_key.include? "-----BEGIN RSA PRIVATE KEY-----")
      assert !(private_key.include? "-----END RSA PRIVATE KEY-----")
      refute_equal private_key, formatted_private_key
      assert !(formatted_private_key.include? "-----BEGIN RSA PRIVATE KEY-----")
      assert !(formatted_private_key.include? "-----END RSA PRIVATE KEY-----")
    end

    it "return formatted private_key with head from private_key with head" do
      private_key = ruby_saml_key_text
      private_key = private_key.gsub(' RSA ', ' ')
      formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key, true)
      assert private_key.include? "-----BEGIN PRIVATE KEY-----"
      assert private_key.include? "-----END PRIVATE KEY-----"
      assert_equal private_key, formatted_private_key
      assert formatted_private_key.include? "-----BEGIN PRIVATE KEY-----"
      assert formatted_private_key.include? "-----END PRIVATE KEY-----"
    end

    it "return formatted RSA private_key with head from private_key without head" do
      private_key = ruby_saml_key_text
      private_key = private_key.gsub(' RSA ', ' ')
      private_key = private_key.delete("\n\r\x0D")
      private_key = private_key.gsub('-----BEGIN PRIVATE KEY-----', '')
      private_key = private_key.gsub('-----END PRIVATE KEY-----', '')
      formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key, true)
      assert !(private_key.include? "-----BEGIN PRIVATE KEY-----")
      assert !(private_key.include? "-----END PRIVATE KEY-----")
      refute_equal private_key, formatted_private_key
      assert formatted_private_key.include? "-----BEGIN RSA PRIVATE KEY-----"
      assert formatted_private_key.include? "-----END RSA PRIVATE KEY-----"
    end

    it "return formatted RSA private_key without head from private_key with head" do
      private_key = ruby_saml_key_text
      private_key = private_key.gsub(' RSA ', ' ')
      formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key, false)
      assert private_key.include? "-----BEGIN PRIVATE KEY-----"
      assert private_key.include? "-----END PRIVATE KEY-----"
      refute_equal private_key, formatted_private_key
      assert !(formatted_private_key.include? "-----BEGIN PRIVATE KEY-----")
      assert !(formatted_private_key.include? "-----END PRIVATE KEY-----")
      assert !(formatted_private_key.include? "-----BEGIN RSA PRIVATE KEY-----")
      assert !(formatted_private_key.include? "-----END RSA PRIVATE KEY-----")
      assert private_key.include? formatted_private_key
    end

    it "return formatted private_key without head from private_key without head" do
      private_key = ruby_saml_key_text
      private_key = private_key.gsub(' RSA ', ' ')
      private_key = private_key.delete("\n\r\x0D")
      private_key = private_key.gsub('-----BEGIN PRIVATE KEY-----', '')
      private_key = private_key.gsub('-----END PRIVATE KEY-----', '')
      formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key, false)
      assert !(private_key.include? "-----BEGIN PRIVATE KEY-----")
      assert !(private_key.include? "-----END PRIVATE KEY-----")
      refute_equal private_key, formatted_private_key
      assert !(formatted_private_key.include? "-----BEGIN PRIVATE KEY-----")
      assert !(formatted_private_key.include? "-----END PRIVATE KEY-----")
      assert !(formatted_private_key.include? "-----BEGIN RSA PRIVATE KEY-----")
      assert !(formatted_private_key.include? "-----END RSA PRIVATE KEY-----")
    end
  end

  describe "#format method working" do
    it "raise nested asn1 error, valid cert but with bad format (with heads)" do
      cert = ruby_saml_cert_text
      cert = cert.gsub("\n", "\n ")

      assert_raises(OpenSSL::X509::CertificateError, "nested asn1 error") do
        x509 = OpenSSL::X509::Certificate.new(cert)
      end
    end

    it "true, valid cert but with bad format (with heads) formated" do
      cert = ruby_saml_cert_text
      cert = cert.gsub("\n", "\n ")

      cert_pem = OpenSSL::X509::Certificate.new(OneLogin::RubySaml::Utils.format_cert(cert)).to_pem
      assert_equal ruby_saml_cert_text, cert_pem
    end

    it "valid false, valid cert but with without head and footer" do
      cert = ruby_saml_cert_text
      cert = cert.delete("\n\r\x0D")
      cert = cert.gsub('-----BEGIN CERTIFICATE-----', '')
      cert = cert.gsub('-----END CERTIFICATE-----', '')      

      assert_raises(OpenSSL::X509::CertificateError, "nested asn1 error") do
        x509 = OpenSSL::X509::Certificate.new(cert)
      end
    end

    it "true,  cert but with bad without head and footer formated" do
      cert = ruby_saml_cert_text
      cert = cert.delete("\n\r\x0D")
      cert = cert.gsub('-----BEGIN CERTIFICATE-----', '')
      cert = cert.gsub('-----END CERTIFICATE-----', '')      

      cert_pem = OpenSSL::X509::Certificate.new(OneLogin::RubySaml::Utils.format_cert(cert)).to_pem
      assert_equal ruby_saml_cert_text, cert_pem
    end
  end

end
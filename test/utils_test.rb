require "test_helper"

class UtilsTest < Minitest::Test
  describe ".format_cert" do
    let(:valid_certificate) do
      read_certificate("valid_certificate")
    end

    it "returns empty string when the cert is an empty string" do
      cert = ""
      assert_equal "", OneLogin::RubySaml::Utils.format_cert(cert)
    end

    it "returns nil when the cert is nil" do
      cert = nil
      assert_equal nil, OneLogin::RubySaml::Utils.format_cert(cert)
    end

    it "returns the certificate when it is valid" do
      assert_equal valid_certificate, OneLogin::RubySaml::Utils.format_cert(valid_certificate)
    end

    it "reformats the certificate when there are spaces and no line breaks" do
      invalid_certificate1 = read_certificate("invalid_certificate1")
      assert_equal valid_certificate, OneLogin::RubySaml::Utils.format_cert(invalid_certificate1)
    end

    it "reformats the certificate when there are spaces and no headers" do
      invalid_certificate2 = read_certificate("invalid_certificate2")
      assert_equal valid_certificate, OneLogin::RubySaml::Utils.format_cert(invalid_certificate2)
    end

    it "reformats the certificate when there line breaks and no headers" do
      invalid_certificate3 = read_certificate("invalid_certificate3")
      assert_equal valid_certificate, OneLogin::RubySaml::Utils.format_cert(invalid_certificate3)
    end
  end

  describe ".format_private_key" do
    let(:valid_private_key) do
      read_certificate("valid_private_key")
    end

    it "returns empty string when the private key is an empty string" do
      private_key = ""
      assert_equal "", OneLogin::RubySaml::Utils.format_private_key(private_key)
    end

    it "returns nil when the private key is nil" do
      private_key = nil
      assert_equal nil, OneLogin::RubySaml::Utils.format_private_key(private_key)
    end

    it "returns the private key when it is valid" do
      assert_equal valid_private_key, OneLogin::RubySaml::Utils.format_private_key(valid_private_key)
    end

    it "reformats the private key when there are spaces and no line breaks" do
      invalid_private_key1 = read_certificate("invalid_private_key1")
      assert_equal valid_private_key, OneLogin::RubySaml::Utils.format_private_key(invalid_private_key1)
    end

    it "reformats the private key when there are spaces and no headers" do
      invalid_private_key2 = read_certificate("invalid_private_key2")
      assert_equal valid_private_key, OneLogin::RubySaml::Utils.format_private_key(invalid_private_key2)
    end

    it "reformats the private key when there line breaks and no headers" do
      invalid_private_key3 = read_certificate("invalid_private_key3")
      assert_equal valid_private_key, OneLogin::RubySaml::Utils.format_private_key(invalid_private_key3)
    end

    describe "an RSA public key" do
      let(:valid_rsa_private_key) do
        read_certificate("valid_rsa_private_key")
      end

      it "returns the private key when it is valid" do
        assert_equal valid_rsa_private_key, OneLogin::RubySaml::Utils.format_private_key(valid_rsa_private_key)
      end

      it "reformats the private key when there are spaces and no line breaks" do
        invalid_rsa_private_key1 = read_certificate("invalid_rsa_private_key1")
        assert_equal valid_rsa_private_key, OneLogin::RubySaml::Utils.format_private_key(invalid_rsa_private_key1)
      end

      it "reformats the private key when there are spaces and no headers" do
        invalid_rsa_private_key2 = read_certificate("invalid_rsa_private_key2")
        assert_equal valid_private_key, OneLogin::RubySaml::Utils.format_private_key(invalid_rsa_private_key2)
      end

      it "reformats the private key when there line breaks and no headers" do
        invalid_rsa_private_key3 = read_certificate("invalid_rsa_private_key3")
        assert_equal valid_private_key, OneLogin::RubySaml::Utils.format_private_key(invalid_rsa_private_key3)
      end
    end
  end
end

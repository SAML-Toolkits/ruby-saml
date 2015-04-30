require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/utils'

class UtilsTest < Minitest::Test

  describe "Utils" do

    describe "format_private_key" do
      let(:private_key) { File.read(File.expand_path('../certificates/ruby-saml.key', __FILE__)) }
      let(:unformatted_private_key) { private_key.gsub(/[\n\r\x0D]/, "") }
      let(:ugly_private_key) do
        unformatted_private_key.insert(61, "\n").insert(104, "\n") \
          .insert(120, "\n").insert(203, "\n").insert(341, "\n") \
          .insert(410, "\n").insert(464, "\n").insert(715, "\n")
      end

      it "doesn't change a well-formatted key" do
        assert_equal private_key, OneLogin::RubySaml::Utils.format_private_key(private_key)
      end

      it "formats a key with no newlines" do
        assert_equal private_key, OneLogin::RubySaml::Utils.format_private_key(unformatted_private_key)
      end

      it "formats an ugly key with random newlines" do
        assert_equal private_key, OneLogin::RubySaml::Utils.format_private_key(ugly_private_key)
      end

      it "returns only the material if 'heads' parameter is false" do
        formatted_key = OneLogin::RubySaml::Utils.format_private_key(private_key, false)
        refute_match /-----BEGIN RSA PRIVATE KEY-----/, formatted_key
        refute_match /-----END RSA PRIVATE KEY-----/, formatted_key
      end

      it "returns headers if 'heads' parameter is true" do
        formatted_key = OneLogin::RubySaml::Utils.format_private_key(private_key, true)
        assert_match /-----BEGIN RSA PRIVATE KEY-----/, formatted_key
        assert_match /-----END RSA PRIVATE KEY-----/, formatted_key
      end
    end
  end

end

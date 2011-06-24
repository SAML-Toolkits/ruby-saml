require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class SettingsTest < Test::Unit::TestCase

  context "Settings" do
    setup do
      @settings = Onelogin::Saml::Settings.new
    end
    should "should provide getters and settings" do
      accessors = [
        :assertion_consumer_service_url, :issuer, :sp_name_qualifier, :sp_name_qualifier,
        :idp_sso_target_url, :idp_cert_fingerprint, :name_identifier_format
      ]

      accessors.each do |accessor|
        value = Kernel.rand
        @settings.send("#{accessor}=".to_sym, value)
        assert_equal value, @settings.send(accessor)
      end
    end
  end

end

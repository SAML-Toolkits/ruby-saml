require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/settings'

class SettingsTest < Minitest::Test

  describe "Settings" do
    before do
      @settings = OneLogin::RubySaml::Settings.new
    end

    it "should provide getters and settings" do
      accessors = [
        :idp_entity_id, :idp_sso_target_url, :idp_slo_target_url, :idp_cert, :idp_cert_fingerprint,
        :issuer, :assertion_consumer_service_url, :assertion_consumer_service_binding,
        :single_logout_service_url, :single_logout_service_binding,
        :sp_name_qualifier, :name_identifier_format, :name_identifier_value,
        :sessionindex, :attributes_index, :passive, :force_authn,
        :compress_request, :double_quote_xml_attribute_values, :protocol_binding,
        :security, :certificate, :private_key,
        :authn_context, :authn_context_comparison, :authn_context_decl_ref,
        :assertion_consumer_logout_service_url,
        :assertion_consumer_logout_service_binding
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
          :attributes_index => 30,
          :passive => true,
          :protocol_binding => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      }
      @settings = OneLogin::RubySaml::Settings.new(config)

      config.each do |k,v|
        assert_equal v, @settings.send(k)
      end
    end

    it "create settings from hash with assertion_consumer_logout" do

      config = {
          :assertion_consumer_logout_service_url => "http://app.muda.no/sso",
          :assertion_consumer_logout_service_binding => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          :issuer => "http://muda.no",
          :sp_name_qualifier => "http://sso.muda.no",
          :idp_sso_target_url => "http://sso.muda.no/sso",
          :idp_slo_target_url => "http://sso.muda.no/slo",
          :idp_cert_fingerprint => "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
          :name_identifier_format => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          :attributes_index => 30,
          :passive => true,
          :protocol_binding => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      }
      @settings = OneLogin::RubySaml::Settings.new(config)

      config.each do |k,v|
        assert_equal v, @settings.send(k)
      end

      assert_equal @settings.single_logout_service_url(), config[:assertion_consumer_logout_service_url]
      assert_equal @settings.single_logout_service_binding(), config[:assertion_consumer_logout_service_binding]
      @settings.single_logout_service_binding = nil
      assert_equal @settings.single_logout_service_binding(), config[:assertion_consumer_logout_service_binding]
    end

    it "configure attribute service attributes correctly" do
      @settings = OneLogin::RubySaml::Settings.new
      @settings.attribute_consuming_service.configure do
        service_name "Test Service"
        add_attribute :name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name"
      end

      assert_equal @settings.attribute_consuming_service.configured?, true
      assert_equal @settings.attribute_consuming_service.name, "Test Service"
      assert_equal @settings.attribute_consuming_service.attributes, [{:name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name" }]
    end

    it "does not modify default security settings" do
      settings = OneLogin::RubySaml::Settings.new
      settings.security[:authn_requests_signed] = true
      settings.security[:embed_sign] = true
      settings.security[:digest_method] = XMLSecurity::Document::SHA256
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256

      new_settings = OneLogin::RubySaml::Settings.new
      assert_equal new_settings.security[:authn_requests_signed], false
      assert_equal new_settings.security[:embed_sign], false
      assert_equal new_settings.security[:digest_method], XMLSecurity::Document::SHA1
      assert_equal new_settings.security[:signature_method], XMLSecurity::Document::RSA_SHA1
    end
  end
end

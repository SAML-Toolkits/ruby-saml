require_relative 'test_helper'

require 'ruby_saml/settings'

class SettingsDeprecationsTest < Minitest::Test

  describe "Settings Deprecations" do
    before do
      @settings = RubySaml::Settings.new
    end

    describe 'replaced deprecations' do
      {
        issuer: :sp_entity_id,
        certificate: :sp_cert,
        private_key: :sp_private_key,
        idp_sso_target_url: :idp_sso_service_url,
        idp_slo_target_url: :idp_slo_service_url,
        assertion_consumer_service_url: :sp_assertion_consumer_service_url,
        assertion_consumer_service_binding: :sp_assertion_consumer_service_binding,
        assertion_consumer_logout_service_url: :sp_slo_service_url,
        assertion_consumer_logout_service_binding: :sp_slo_service_binding,
        single_logout_service_url: :sp_slo_service_url,
        single_logout_service_binding: :sp_slo_service_binding
      }.each do |old_method, new_method|
        it ":#{old_method} is aliased to :#{new_method}" do
          @settings.send(:"#{new_method}=", 'Dummy')

          assert_equal 'Dummy', @settings.send(:"#{old_method}")
          assert_equal 'Dummy', @settings.send(:"#{new_method}")
        end

        it ":#{old_method}= is aliased to :#{new_method}=" do
          @settings.send(:"#{old_method}=", 'Dummy')

          assert_equal 'Dummy', @settings.send(:"#{old_method}")
          assert_equal 'Dummy', @settings.send(:"#{new_method}")
        end

        it ":#{old_method} logs a deprecation warning" do
          RubySaml::Logging.expects(:deprecate).with(regexp_matches(/#{old_method}.+#{new_method}/))
          @settings.send(:"#{old_method}")
        end

        it ":#{old_method}= logs a deprecation warning" do
          RubySaml::Logging.expects(:deprecate).with(regexp_matches(/#{old_method}.+#{new_method}/))
          @settings.send(:"#{old_method}=", 'Dummy')
        end

        it ":#{new_method} logs a deprecation warning" do
          RubySaml::Logging.expects(:deprecate).never
          @settings.send(:"#{new_method}")
        end

        it ":#{new_method}= logs a deprecation warning" do
          RubySaml::Logging.expects(:deprecate).never
          @settings.send(:"#{new_method}=", 'Dummy')
        end
      end
    end

    describe 'nullified deprecations' do
      %i[ certificate_new
          compress_request
          compress_response ].each do |old_method|
        it ":#{old_method} is an accessor" do
          @settings.send(:"#{old_method}=", 'Dummy')

          assert_equal 'Dummy', @settings.send(:"#{old_method}")
        end

        it ":#{old_method} logs a deprecation warning" do
          RubySaml::Logging.expects(:deprecate).with(regexp_matches(/#{old_method}/))
          @settings.send(:"#{old_method}")
        end

        it ":#{old_method}= logs a deprecation warning" do
          RubySaml::Logging.expects(:deprecate).with(regexp_matches(/#{old_method}/))
          @settings.send(:"#{old_method}=", 'Dummy')
        end
      end
    end
  end
end

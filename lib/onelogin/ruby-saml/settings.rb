module Onelogin
  module Saml

    class PermissiveAssertionIdValidator
      def valid?(id)
        true
      end
    end
    
    class Settings
      def initialize(overrides = {})
        config = DEFAULTS.merge(overrides)
        config.each do |k,v|
          acc = "#{k.to_s}=".to_sym
          self.send(acc, v) if self.respond_to? acc
        end
      end
      attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
      attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :idp_cert, :name_identifier_format
      attr_accessor :authn_context
      attr_accessor :idp_slo_target_url
      attr_accessor :name_identifier_value
      attr_accessor :sessionindex
      attr_accessor :assertion_consumer_logout_service_url
      attr_accessor :compress_request
      attr_accessor :double_quote_xml_attribute_values
      attr_accessor :assertion_id_validator

      private
      
      DEFAULTS = {:compress_request => true, :double_quote_xml_attribute_values => false, :assertion_id_validator => PermissiveAssertionIdValidator.new}
    end

  end
end

module Onelogin
  module Saml
    class Settings
      def initialize(config = {})
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
    end
  end
end

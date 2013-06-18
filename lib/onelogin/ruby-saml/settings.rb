module OneLogin
  module RubySaml
    class Settings
      def initialize(overrides = {})
        config = DEFAULTS.merge(overrides)
        config.each do |k,v|
          acc = "#{k.to_s}=".to_sym
          self.send(acc, v) if self.respond_to? acc
        end
      end
      attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
      attr_accessor :assertion_consumer_service_binding
      attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :idp_cert, :name_identifier_format
      attr_accessor :authn_context
      attr_accessor :idp_slo_target_url
      attr_accessor :name_identifier_value
      attr_accessor :sessionindex
      attr_accessor :assertion_consumer_logout_service_url
      attr_accessor :assertion_consumer_logout_service_binding
      attr_accessor :compress_request
      attr_accessor :double_quote_xml_attribute_values
      attr_accessor :passive
      attr_accessor :protocol_binding
      attr_accessor :attributes_index
      attr_accessor :sign_request, :certificate, :private_key, :digest_method, :signature_method

      def simple_sign_request
        assertion_consumer_service_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign'
      end

      private

      DEFAULTS = {
        :assertion_consumer_service_binding        => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        :assertion_consumer_logout_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        :compress_request                          => true,
        :sign_request                              => false,
        :double_quote_xml_attribute_values         => false,
        :digest_method                             => "SHA1",
        :signature_method                          => "SHA1"
      }
    end
  end
end

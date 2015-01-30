module OneLogin
  module RubySaml
    class Settings
      def initialize(overrides = {})
        config = DEFAULTS.merge(overrides)
        config.each do |k,v|
          acc = "#{k.to_s}=".to_sym
          self.send(acc, v) if self.respond_to? acc
        end
        @attribute_consuming_service = AttributeService.new
      end

      # IdP Data
      attr_accessor :idp_entity_id
      attr_accessor :idp_sso_target_url
      attr_accessor :idp_slo_target_url
      attr_accessor :idp_cert
      attr_accessor :idp_cert_fingerprint
      # SP Data
      attr_accessor :issuer
      attr_accessor :assertion_consumer_service_url
      attr_accessor :assertion_consumer_service_binding
      attr_accessor :sp_name_qualifier
      attr_accessor :name_identifier_format
      attr_accessor :name_identifier_value
      attr_accessor :sessionindex
      attr_accessor :compress_request
      attr_accessor :compress_response
      attr_accessor :double_quote_xml_attribute_values
      attr_accessor :passive
      attr_accessor :protocol_binding
      attr_accessor :attributes_index
      attr_accessor :force_authn
      attr_accessor :security
      attr_accessor :certificate
      attr_accessor :private_key
      attr_accessor :authn_context
      attr_accessor :authn_context_comparison
      attr_accessor :authn_context_decl_ref
      attr_reader :attribute_consuming_service
      attr_accessor :idp_list
      attr_accessor :proxy_count
      attr_accessor :requester_id
      # Compability
      attr_accessor :assertion_consumer_logout_service_url
      attr_accessor :assertion_consumer_logout_service_binding

      def single_logout_service_url()
        val = nil
        if @single_logout_service_url.nil?
          if @assertion_consumer_logout_service_url
            val = @assertion_consumer_logout_service_url
          end
        else
          val = @single_logout_service_url
        end
        val
      end

      # setter
      def single_logout_service_url=(val)
        @single_logout_service_url = val
      end

      def single_logout_service_binding()
        val = nil
        if @single_logout_service_binding.nil?
          if @assertion_consumer_logout_service_binding
            val = @assertion_consumer_logout_service_binding
          end
        else
          val = @single_logout_service_binding
        end
        val
      end

      # setter
      def single_logout_service_binding=(val)
        @single_logout_service_binding = val
      end

      def get_sp_cert
        cert = nil
        if self.certificate
          formated_cert = OneLogin::RubySaml::Utils.format_cert(self.certificate)
          cert = OpenSSL::X509::Certificate.new(formated_cert)
        end
        cert
      end

      def get_sp_key
        private_key = nil
        if self.private_key
          formated_private_key = OneLogin::RubySaml::Utils.format_private_key(self.private_key)
          private_key = OpenSSL::PKey::RSA.new(formated_private_key)
        end
        private_key
      end

      private

      DEFAULTS = {
        :assertion_consumer_service_binding        => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        :single_logout_service_binding             => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        :compress_request                          => true,
        :compress_response                         => true,
        :security                                  => {
          :authn_requests_signed    => false,
          :logout_requests_signed   => false,
          :logout_responses_signed   => false,
          :embed_sign               => false,
          :digest_method            => XMLSecurity::Document::SHA1,
          :signature_method         => XMLSecurity::Document::SHA1
        },
        :double_quote_xml_attribute_values         => false,
      }
    end
  end
end

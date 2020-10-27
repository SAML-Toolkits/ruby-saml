require "xml_security"
require "onelogin/ruby-saml/utils"

module OneLogin
  module RubySaml
    class Settings
      def initialize(overrides = {}, keep_security_attributes = false)
        if keep_security_attributes
           security_attributes = overrides.delete(:security) || {}
           config = DEFAULTS.merge(overrides)
           config[:security] = DEFAULTS[:security].merge(security_attributes)
         else
           config = DEFAULTS.merge(overrides)
         end

         config.each do |k,v|
           acc = "#{k.to_s}=".to_sym
           if respond_to? acc
             value = v.is_a?(Hash) ? v.dup : v
             send(acc, value)
           end
         end
      end

      #idp data
      attr_accessor :idp_sso_target_url
      attr_accessor :idp_cert_fingerprint
      attr_accessor :idp_cert
      attr_accessor :idp_slo_target_url
      #sp data
      attr_accessor :sp_entity_id
      attr_accessor :assertion_consumer_service_url
      attr_accessor :authn_context
      attr_accessor :sp_name_qualifier
      attr_accessor :name_identifier_format
      attr_accessor :name_identifier_value
      attr_accessor :name_identifier_value_requested
      attr_accessor :sessionindex
      attr_accessor :assertion_consumer_logout_service_url
      attr_accessor :compress_request
      attr_accessor :compress_response
      attr_accessor :double_quote_xml_attribute_values
      attr_accessor :force_authn
      attr_accessor :passive
      attr_accessor :protocol_binding
      attr_accessor :certificate
      attr_accessor :private_key
      # Work-flow
      attr_accessor :security
      # Compability
      attr_accessor :issuer
      attr_accessor :assertion_consumer_logout_service_url
      attr_accessor :assertion_consumer_logout_service_binding

      # @return [String] SP Entity ID
      #
      def sp_entity_id
        val = nil
        if @sp_entity_id.nil?
          if @issuer
            val = @issuer
          end
        else
          val = @sp_entity_id
        end
        val
      end

       # Setter for SP Entity ID.
      # @param val [String].
      #
      def sp_entity_id=(val)
        @sp_entity_id = val
      end

      # @return [String] Single Logout Service URL.
      #
      def single_logout_service_url
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

      # Setter for the Single Logout Service URL.
      # @param url [String].
      #
      def single_logout_service_url=(url)
        @single_logout_service_url = url
      end

      # @return [String] Single Logout Service Binding.
      #
      def single_logout_service_binding
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

      # Setter for Single Logout Service Binding.
      #
      # (Currently we only support "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
      # @param url [String]
      #
      def single_logout_service_binding=(url)
        @single_logout_service_binding = url
      end

      # Calculates the fingerprint of the IdP x509 certificate.
      # @return [String] The fingerprint
      #
      def get_fingerprint
        idp_cert_fingerprint || begin
          idp_cert = get_idp_cert
          if idp_cert
            Digest::SHA1.hexdigest(idp_cert.to_der).upcase.scan(/../).join(":")
          end
        end
      end

      # @return [OpenSSL::X509::Certificate|nil] Build the IdP certificate from the settings (previously format it)
      #
      def get_idp_cert
        return nil if idp_cert.nil?

        if idp_cert.respond_to?(:to_pem)
          idp_cert
        else
          return nil if idp_cert.empty?
          formatted_cert = OneLogin::RubySaml::Utils.format_cert(idp_cert)
          OpenSSL::X509::Certificate.new(formatted_cert)
        end
      end

      # @return [OpenSSL::X509::Certificate|nil] Build the SP certificate from the settings (previously format it)
      #
      def get_sp_cert
        return nil if certificate.nil? || certificate.empty?

        formatted_cert = OneLogin::RubySaml::Utils.format_cert(certificate)
        OpenSSL::X509::Certificate.new(formatted_cert)
      end

      # @return [OpenSSL::X509::Certificate|nil] Build the New SP certificate from the settings (previously format it)
      #
      def get_sp_cert_new
        return nil if certificate_new.nil? || certificate_new.empty?

        formatted_cert = OneLogin::RubySaml::Utils.format_cert(certificate_new)
        OpenSSL::X509::Certificate.new(formatted_cert)
      end

      # @return [OpenSSL::PKey::RSA] Build the SP private from the settings (previously format it)
      #
      def get_sp_key
        return nil if private_key.nil? || private_key.empty?

        formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(private_key)
        OpenSSL::PKey::RSA.new(formatted_private_key)
      end

      private

      DEFAULTS = {
        :compress_request => true,
        :compress_response => true,
        :double_quote_xml_attribute_values => false,
        :assertion_consumer_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".freeze,
        :single_logout_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".freeze,
        :security                                  => {
          :authn_requests_signed      => false,
          :logout_requests_signed     => false,
          :logout_responses_signed    => false,
          :embed_sign                 => false,
          :digest_method              => XMLSecurity::Document::SHA1,
          :signature_method           => XMLSecurity::Document::RSA_SHA1
        }.freeze
      }.freeze
    end
  end
end

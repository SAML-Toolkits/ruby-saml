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
      attr_accessor :assertion_consumer_service_url, :sp_entity_id, :sp_name_qualifier
      attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :idp_cert, :name_identifier_format
      attr_accessor :authn_context
      attr_accessor :idp_slo_target_url
      attr_accessor :name_identifier_value
      attr_accessor :name_identifier_value_requested
      attr_accessor :sessionindex
      attr_accessor :assertion_consumer_logout_service_url
      attr_accessor :compress_request
      attr_accessor :double_quote_xml_attribute_values
      attr_accessor :force_authn
      attr_accessor :passive
      attr_accessor :protocol_binding

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

      private

      DEFAULTS = {
        :compress_request => true,
        :double_quote_xml_attribute_values => false,
        :assertion_consumer_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".freeze,
        :single_logout_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".freeze
      }
    end
  end
end

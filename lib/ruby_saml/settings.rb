# frozen_string_literal: true

require "ruby_saml/xml"
require "ruby_saml/attribute_service"
require "ruby_saml/utils"
require "ruby_saml/validation_error"

# Only supports SAML 2.0
module RubySaml

  # SAML2 Toolkit Settings
  #
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
        acc = "#{k}=".to_sym
        if respond_to? acc
          value = v.is_a?(Hash) ? v.dup : v
          send(acc, value)
        end
      end
      @attribute_consuming_service = AttributeService.new
    end

    # IdP Data
    attr_accessor :idp_entity_id
    attr_accessor :idp_sso_service_url
    attr_accessor :idp_slo_service_url
    attr_accessor :idp_slo_response_service_url
    attr_accessor :idp_cert
    attr_accessor :idp_cert_fingerprint
    attr_accessor :idp_cert_fingerprint_algorithm
    attr_accessor :idp_cert_multi
    attr_accessor :idp_attribute_names
    attr_accessor :idp_name_qualifier
    attr_accessor :valid_until

    # SP Data
    attr_accessor :sp_entity_id
    attr_accessor :sp_assertion_consumer_service_url
    attr_reader   :sp_assertion_consumer_service_binding
    attr_accessor :sp_slo_service_url
    attr_reader   :sp_slo_service_binding
    attr_accessor :sp_cert
    attr_accessor :sp_cert_multi
    attr_accessor :sp_private_key
    attr_accessor :sp_name_qualifier
    attr_accessor :name_identifier_format
    attr_accessor :name_identifier_value
    attr_accessor :name_identifier_value_requested
    attr_accessor :sessionindex
    attr_accessor :double_quote_xml_attribute_values
    attr_accessor :message_max_bytesize
    attr_accessor :passive
    attr_reader   :protocol_binding
    attr_accessor :attributes_index
    attr_accessor :force_authn
    attr_accessor :authn_context
    attr_accessor :authn_context_comparison
    attr_accessor :authn_context_decl_ref
    attr_reader :attribute_consuming_service

    # Workflow
    attr_accessor :security
    attr_accessor :soft

    # @return [String] IdP Single Sign On Service Binding
    #
    def idp_sso_service_binding
      @idp_sso_service_binding || Utils::BINDINGS[:redirect]
    end

    # Setter for IdP Single Sign On Service Binding
    # @param value [String, Symbol].
    #
    def idp_sso_service_binding=(value)
      @idp_sso_service_binding = get_binding(value)
    end

    # @return [String] IdP Single Logout Service Binding
    #
    def idp_slo_service_binding
      @idp_slo_service_binding || Utils::BINDINGS[:redirect]
    end

    # Setter for IdP Single Logout Service Binding
    # @param value [String, Symbol].
    #
    def idp_slo_service_binding=(value)
      @idp_slo_service_binding = get_binding(value)
    end

    # Setter for SP Protocol Binding
    # @param value [String, Symbol].
    #
    def protocol_binding=(value)
      @protocol_binding = get_binding(value)
    end

    # Setter for SP Assertion Consumer Service Binding
    # @param value [String, Symbol].
    #
    def sp_assertion_consumer_service_binding=(value)
      @sp_assertion_consumer_service_binding = get_binding(value)
    end

    # Setter for Single Logout Service Binding.
    #
    # (Currently we only support "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
    # @param value [String, Symbol]
    #
    def sp_slo_service_binding=(value)
      @sp_slo_service_binding = get_binding(value)
    end

    # Calculates the fingerprint of the IdP x509 certificate.
    # @return [String] The fingerprint
    #
    def get_fingerprint
      idp_cert_fingerprint || begin
        idp_cert = get_idp_cert
        if idp_cert
          fingerprint_alg = RubySaml::XML::BaseDocument.new.algorithm(idp_cert_fingerprint_algorithm).new
          fingerprint_alg.hexdigest(idp_cert.to_der).upcase.scan(/../).join(":")
        end
      end
    end

    # @return [OpenSSL::X509::Certificate|nil] Build the IdP certificate from the settings (previously format it)
    #
    def get_idp_cert
      RubySaml::Utils.build_cert_object(idp_cert)
    end

    # @return [Hash with 2 arrays of OpenSSL::X509::Certificate] Build multiple IdP certificates from the settings.
    #
    def get_idp_cert_multi
      return nil if idp_cert_multi.nil? || idp_cert_multi.empty?

      raise ArgumentError.new("Invalid value for idp_cert_multi") unless idp_cert_multi.is_a?(Hash)

      certs = {signing: [], encryption: [] }

      %i[signing encryption].each do |type|
        certs_for_type = idp_cert_multi[type] || idp_cert_multi[type.to_s]
        next if !certs_for_type || certs_for_type.empty?

        certs_for_type.each do |idp_cert|
          certs[type].push(RubySaml::Utils.build_cert_object(idp_cert))
        end
      end

      certs
    end

    # @return [Hash<Symbol, Array<Array<OpenSSL::X509::Certificate, OpenSSL::PKey::RSA>>>]
    #   Build the SP certificates and private keys from the settings. If
    #   check_sp_cert_expiration is true, only returns certificates and private keys
    #   that are not expired.
    def get_sp_certs
      certs = get_all_sp_certs
      return certs unless security[:check_sp_cert_expiration]

      active_certs = { signing: [], encryption: [] }
      certs.each do |use, pairs|
        next if pairs.empty?

        pairs = pairs.select { |cert, _| !cert || RubySaml::Utils.is_cert_active(cert) }
        raise RubySaml::ValidationError.new("The SP certificate expired.") if pairs.empty?

        active_certs[use] = pairs.freeze
      end
      active_certs.freeze
    end

    # @return [Array<OpenSSL::X509::Certificate, OpenSSL::PKey::RSA>]
    #   The SP signing certificate and private key.
    def get_sp_signing_pair
      get_sp_certs[:signing].first
    end

    # @return [OpenSSL::X509::Certificate] The SP signing certificate.
    # @deprecated Use get_sp_signing_pair or get_sp_certs instead.
    def get_sp_cert
      node = get_sp_signing_pair
      node[0] if node
    end

    # @return [OpenSSL::PKey::RSA] The SP signing key.
    def get_sp_signing_key
      node = get_sp_signing_pair
      node[1] if node
    end

    # @deprecated Use get_sp_signing_key or get_sp_certs instead.
    alias_method :get_sp_key, :get_sp_signing_key

    # @return [Array<OpenSSL::PKey::RSA>] The SP decryption keys.
    def get_sp_decryption_keys
      ary = get_sp_certs[:encryption].map { |pair| pair[1] }
      ary.compact!
      ary.uniq!(&:to_pem)
      ary.freeze
    end

    # @return [OpenSSL::X509::Certificate|nil] Build the New SP certificate from the settings.
    #
    # @deprecated Use get_sp_certs instead
    def get_sp_cert_new
      node = get_sp_certs[:signing].last
      node[0] if node
    end

    def get_binding(value)
      return unless value

      Utils::BINDINGS[value.to_sym] || value
    end

    DEFAULTS = {
      sp_assertion_consumer_service_binding: Utils::BINDINGS[:post],
      sp_slo_service_binding: Utils::BINDINGS[:redirect],
      idp_cert_fingerprint_algorithm: RubySaml::XML::Document::SHA256,
      message_max_bytesize: 250_000,
      soft: true,
      double_quote_xml_attribute_values: false,
      security: {
        authn_requests_signed: false,
        logout_requests_signed: false,
        logout_responses_signed: false,
        want_assertions_signed: false,
        want_assertions_encrypted: false,
        want_name_id: false,
        metadata_signed: false,
        digest_method: RubySaml::XML::Document::SHA256,
        signature_method: RubySaml::XML::Document::RSA_SHA256,
        check_idp_cert_expiration: false,
        check_sp_cert_expiration: false,
        strict_audience_validation: false,
        lowercase_url_encoding: false
      }.freeze
    }.freeze

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
    }.each do |old_param, new_param|
      # @deprecated Will raise NotImplementedError in v3.0.0
      define_method(old_param) do
        replaced_deprecation(old_param, new_param)
        send(new_param)
      end

      # @deprecated Will raise NotImplementedError in v3.0.0
      define_method(:"#{old_param}=") do |value|
        replaced_deprecation(old_param, new_param)
        send(:"#{new_param}=", value)
      end
    end

    # @deprecated Will raise NotImplementedError in v2.1.0
    def certificate_new
      certificate_new_deprecation
      @certificate_new
    end

    # @deprecated Will raise NotImplementedError in v2.1.0
    def certificate_new=(value)
      certificate_new_deprecation
      @certificate_new = value
    end

    # @deprecated Will raise NotImplementedError in v2.1.0
    def compress_request
      compress_deprecation('compress_request', 'idp_sso_service_binding')
      defined?(@compress_request) ? @compress_request : true
    end

    # @deprecated Will raise NotImplementedError in v2.1.0
    def compress_request=(value)
      compress_deprecation('compress_request', 'idp_sso_service_binding')
      @compress_request = value
    end

    # @deprecated Will raise NotImplementedError in v2.1.0
    def compress_response
      compress_deprecation('compress_response', 'idp_slo_service_binding')
      defined?(@compress_response) ? @compress_response : true
    end

    # @deprecated Will raise NotImplementedError in v2.1.0
    def compress_response=(value)
      compress_deprecation('compress_response', 'idp_slo_service_binding')
      @compress_response = value
    end

    private

    # @deprecated Will be removed in v2.1.0
    def replaced_deprecation(old_param, new_param)
      Logging.deprecate "`RubySaml::Settings##{old_param}` is deprecated and has been renamed to `#{new_param}`. " \
                        "Please replace it 1-for-1 in your code. `#{old_param}` will be removed in RubySaml 3.0.0."
    end

    # @deprecated Will be removed in v2.1.0
    def certificate_new_deprecation
      Logging.deprecate '`RubySaml::Settings#certificate_new` is deprecated and will be removed in RubySaml v2.1.0. ' \
                        'Please set `RubySaml::Settings#sp_cert_multi` instead. ' \
                        'Please refer to documentation as `sp_cert_multi` has a different value type.'
    end

    # @deprecated Will be removed in v2.1.0
    def compress_deprecation(old_param, new_param)
      Logging.deprecate "`RubySaml::Settings##{old_param}` is deprecated and no longer functional. " \
                        'It will be removed in RubySaml 2.1.0. ' \
                        "Its functionality is now handled by `RubySaml::Settings##{new_param}` instead: " \
                        '"HTTP-Redirect" will always be compressed, and "HTTP-POST" will always be uncompressed.'
    end

    # @return [Hash<Symbol, Array<Array<OpenSSL::X509::Certificate, OpenSSL::PKey::RSA>>>]
    #   Build the SP certificates and private keys from the settings. Returns all
    #   certificates and private keys, even if they are expired.
    def get_all_sp_certs
      validate_sp_certs_params!
      get_sp_certs_multi || get_sp_certs_single
    end

    # Validate certificate, certificate_new, private_key, and sp_cert_multi params.
    def validate_sp_certs_params!
      multi    = sp_cert_multi   && !sp_cert_multi.empty?
      cert     = certificate     && !certificate.empty?
      cert_new = certificate_new && !certificate_new.empty?
      pk       = private_key     && !private_key.empty?
      if multi && (cert || cert_new || pk)
        raise ArgumentError.new("Cannot specify both sp_cert_multi and certificate, certificate_new, private_key parameters")
      end
    end

    # Get certs from certificate, certificate_new, and private_key parameters.
    def get_sp_certs_single
      certs = { :signing => [], :encryption => [] }

      sp_key = RubySaml::Utils.build_private_key_object(private_key)
      cert = RubySaml::Utils.build_cert_object(certificate)
      if cert || sp_key
        ary = [cert, sp_key].freeze
        certs[:signing] << ary
        certs[:encryption] << ary
      end

      cert_new = RubySaml::Utils.build_cert_object(certificate_new)
      if cert_new
        ary = [cert_new, sp_key].freeze
        certs[:signing] << ary
        certs[:encryption] << ary
      end

      certs
    end

    # Get certs from get_sp_cert_multi parameter.
    def get_sp_certs_multi
      return if sp_cert_multi.nil? || sp_cert_multi.empty?

      raise ArgumentError.new("sp_cert_multi must be a Hash") unless sp_cert_multi.is_a?(Hash)

      certs = { :signing => [], :encryption => [] }.freeze

      [:signing, :encryption].each do |type|
        certs_for_type = sp_cert_multi[type] || sp_cert_multi[type.to_s]
        next if !certs_for_type || certs_for_type.empty?

        unless certs_for_type.is_a?(Array) && certs_for_type.all? { |cert| cert.is_a?(Hash) }
          raise ArgumentError.new("sp_cert_multi :#{type} node must be an Array of Hashes")
        end

        certs_for_type.each do |pair|
          cert = pair[:certificate] || pair['certificate'] || pair[:cert] || pair['cert']
          key  = pair[:private_key] || pair['private_key'] || pair[:key] || pair['key']

          unless cert && key
            raise ArgumentError.new("sp_cert_multi :#{type} node Hashes must specify keys :certificate and :private_key")
          end

          certs[type] << [
            RubySaml::Utils.build_cert_object(cert),
            RubySaml::Utils.build_private_key_object(key)
          ].freeze
        end
      end

      certs.each { |_, ary| ary.freeze }
      certs
    end
  end
end

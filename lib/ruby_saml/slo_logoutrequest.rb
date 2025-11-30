# frozen_string_literal: true

require 'zlib'
require 'time'
require 'nokogiri'

require "ruby_saml/saml_message"

module RubySaml
  # SAML2 Logout Request (SLO IdP initiated, Parser)
  class SloLogoutrequest < SamlMessage
    include ErrorHandling

    # RubySaml::Settings Toolkit settings
    attr_accessor :settings

    attr_reader :document
    attr_reader :request
    attr_reader :options

    attr_accessor :soft

    # Constructs the Logout Request. A Logout Request Object that is an extension of the SamlMessage class.
    # @param request [String] A UUEncoded Logout Request from the IdP.
    # @param options [Hash]  :settings to provide the RubySaml::Settings object
    #                        Or :allowed_clock_drift for the logout request validation process to allow a clock drift when checking dates with
    #                        Or :relax_signature_validation to accept signatures if no idp certificate registered on settings
    #
    # @raise [ArgumentError] If Request is nil
    #
    def initialize(request, options = {})
      raise ArgumentError.new("Request cannot be nil") if request.nil?

      @errors = []
      @options = options
      @soft = true
      unless options[:settings].nil?
        @settings = options[:settings]

        raise ValidationError.new("Invalid settings type: expected RubySaml::Settings, got #{@settings.class.name}") if !@settings.is_a?(Settings) && !@settings.nil?

        @soft = @settings.respond_to?(:soft) && !@settings.soft.nil? ? @settings.soft : true
        message_max_bytesize = @settings.message_max_bytesize if @settings.respond_to?(:message_max_bytesize)
      end

      @request = RubySaml::XML::Decoder.decode_message(request, message_max_bytesize)
      begin
        @document = RubySaml::XML.safe_load_xml(@request, check_malformed_doc: @soft)
      rescue StandardError => e
        @errors << "XML load failed: #{e.message}" if e.message != 'Empty document'
        return if @soft
        raise ValidationError.new("XML load failed: #{e.message}") if e.message != 'Empty document'
      end

      super()
    end

    def request_id
      id(document)
    end

    # Validates the Logout Request with the default values (soft = true)
    # @param collect_errors [Boolean] Stop validation when first error appears or keep validating.
    # @return [Boolean] TRUE if the Logout Request is valid
    #
    def is_valid?(collect_errors = false)
      validate(collect_errors)
    end

    # @return [String] The NameID of the Logout Request.
    def name_id
      @name_id ||= name_id_node&.text
    end
    alias_method :nameid, :name_id

    # @return [String] The NameID Format of the Logout Request.
    def name_id_format
      @name_id_format ||= name_id_node&.[]('Format')
    end
    alias_method :nameid_format, :name_id_format

    def name_id_node
      @name_id_node ||= begin
        encrypted_node = document.at_xpath("/p:LogoutRequest/a:EncryptedID", { "p" => RubySaml::XML::NS_PROTOCOL, "a" => RubySaml::XML::NS_ASSERTION })
        if encrypted_node
          RubySaml::XML::Decryptor.decrypt_nameid(encrypted_node, settings&.get_sp_decryption_keys)
        else
          document.at_xpath("/p:LogoutRequest/a:NameID", { "p" => RubySaml::XML::NS_PROTOCOL, "a" => RubySaml::XML::NS_ASSERTION })
        end
      end
    end

    # @return [String|nil] Gets the ID attribute from the Logout Request. if exists.
    #
    def id
      super(document)
    end

    # @return [String] Gets the Issuer from the Logout Request.
    #
    def issuer
      @issuer ||= document.at_xpath(
        "/p:LogoutRequest/a:Issuer",
        { "p" => RubySaml::XML::NS_PROTOCOL, "a" => RubySaml::XML::NS_ASSERTION }
      )&.text
    end

    # @return [Time|nil] Gets the NotOnOrAfter Attribute value if exists.
    #
    def not_on_or_after
      @not_on_or_after ||= begin
        node = document.at_xpath(
          "/p:LogoutRequest",
          { "p" => RubySaml::XML::NS_PROTOCOL }
        )

        if (value = node&.attributes&.[]("NotOnOrAfter"))
          Time.parse(value)
        end
      end
    end

    # @return [Array] Gets the SessionIndex if exists (Supported multiple values). Empty Array if none found
    #
    def session_indexes
      document.xpath(
        "/p:LogoutRequest/p:SessionIndex",
        { "p" => RubySaml::XML::NS_PROTOCOL }
      ).map(&:text)
    end

    private

    # returns the allowed clock drift on timing validation
    # @return [Float]
    def allowed_clock_drift
      options[:allowed_clock_drift].to_f.abs + Float::EPSILON
    end

    # Hard aux function to validate the Logout Request
    # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
    # @return [Boolean] TRUE if the Logout Request is valid
    # @raise [ValidationError] if soft == false and validation fails
    #
    def validate(collect_errors = false)
      reset_errors!

      validations = %i[
        validate_request_state
        validate_id
        validate_version
        validate_structure
        validate_not_on_or_after
        validate_issuer
        validate_signature
      ]

      if collect_errors
        validations.each { |validation| send(validation) }
        @errors.empty?
      else
        validations.all? { |validation| send(validation) }
      end
    end

    # Validates that the Logout Request contains an ID
    # If fails, the error is added to the errors array.
    # @return [Boolean] True if the Logout Request contains an ID, otherwise returns False
    #
    def validate_id
      return append_error("Missing ID attribute on Logout Request") if document.nil?

      return true if id
      append_error("Missing ID attribute on Logout Request")
    end

    # Validates the SAML version (2.0)
    # If fails, the error is added to the errors array.
    # @return [Boolean] True if the Logout Request is 2.0, otherwise returns False
    #
    def validate_version
      return append_error("Unsupported SAML version") if document.nil?

      return true if version(document) == "2.0"
      append_error("Unsupported SAML version")
    end

    # Validates the time. (If the logout request was initialized with the :allowed_clock_drift
    # option, the timing validations are relaxed by the allowed_clock_drift value)
    # If fails, the error is added to the errors array
    # @return [Boolean] True if satisfies the conditions, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    def validate_not_on_or_after
      now = Time.now.utc

      if not_on_or_after && now >= (not_on_or_after + allowed_clock_drift)
        return append_error("Current time is on or after NotOnOrAfter (#{now} >= #{not_on_or_after}#{" + #{allowed_clock_drift.ceil}s" if allowed_clock_drift > 0})")
      end

      true
    end

    # Validates the Logout Request against the specified schema.
    # @return [Boolean] True if the XML is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    def validate_structure
      doc_to_analize = @document.nil? ? @request : @document

      check_malformed_doc = check_malformed_doc?(settings)
      unless valid_saml?(doc_to_analize, soft, check_malformed_doc: check_malformed_doc)
        return append_error("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd")
      end

      true
    end

    # Validates that the Logout Request provided in the initialization is not empty,
    # @return [Boolean] True if the required info is found, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    def validate_request_state
      return append_error("Blank logout request") if request.nil? || request.empty?

      true
    end

    # Validates the Issuer of the Logout Request
    # If fails, the error is added to the errors array
    # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    def validate_issuer
      return true if settings.nil? || settings.idp_entity_id.nil? || issuer.nil?

      unless RubySaml::Utils.uri_match?(issuer, settings.idp_entity_id)
        return append_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
      end

      true
    end

    # Validates the Signature if exists and GET parameters are provided
    # @return [Boolean] True if not contains a Signature or if the Signature is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    def validate_signature
      return true if options.nil?
      return true unless options.key? :get_params
      return true unless options[:get_params].key? 'Signature'

      options[:raw_get_params] = RubySaml::Utils.prepare_raw_get_params(options[:raw_get_params], options[:get_params], settings.security[:lowercase_url_encoding])

      if options[:get_params]['SigAlg'].nil? && !options[:raw_get_params]['SigAlg'].nil?
        options[:get_params]['SigAlg'] = CGI.unescape(options[:raw_get_params]['SigAlg'])
      end

      idp_cert = settings.get_idp_cert
      idp_certs = settings.get_idp_cert_multi

      if idp_cert.nil? && (idp_certs.nil? || idp_certs[:signing].empty?)
        return options.key? :relax_signature_validation
      end

      query_string = RubySaml::Utils.build_query_from_raw_parts(
        type: 'SAMLRequest',
        raw_data: options[:raw_get_params]['SAMLRequest'],
        raw_relay_state: options[:raw_get_params]['RelayState'],
        raw_sig_alg: options[:raw_get_params]['SigAlg']
      )

      expired = false
      if idp_certs.nil? || idp_certs[:signing].empty?
        valid = RubySaml::Utils.verify_signature(
          cert: idp_cert,
          sig_alg: options[:get_params]['SigAlg'],
          signature: options[:get_params]['Signature'],
          query_string: query_string
        )
        if valid && settings.security[:check_idp_cert_expiration] && RubySaml::Utils.is_cert_expired(idp_cert)
          expired = true
        end
      else
        valid = false
        idp_certs[:signing].each do |signing_idp_cert|
          valid = RubySaml::Utils.verify_signature(
            cert: signing_idp_cert,
            sig_alg: options[:get_params]['SigAlg'],
            signature: options[:get_params]['Signature'],
            query_string: query_string
          )
          next unless valid

          if settings.security[:check_idp_cert_expiration] && RubySaml::Utils.is_cert_expired(signing_idp_cert)
            expired = true
          end
          break
        end
      end

      if expired
        error_msg = "IdP x509 certificate expired"
        return append_error(error_msg)
      end
      unless valid
        return append_error("Invalid Signature on Logout Request")
      end

      true
    end
  end
end

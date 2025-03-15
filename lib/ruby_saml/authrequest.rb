# frozen_string_literal: true

require "ruby_saml/logging"
require "ruby_saml/saml_message"
require "ruby_saml/utils"
require "ruby_saml/setting_error"

module RubySaml
  # SAML2 Authentication. AuthNRequest (SSO SP initiated, Builder)
  class Authrequest < SamlMessage

    # AuthNRequest ID
    attr_accessor :uuid
    alias_method :request_id, :uuid

    # Creates the AuthNRequest string.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [String] AuthNRequest string that includes the SAMLRequest
    def create(settings, params = {})
      assign_uuid(settings)
      params = create_params(settings, params)
      params_prefix = /\?/.match?(settings.idp_sso_service_url) ? '&' : '?'
      saml_request = CGI.escape(params.delete("SAMLRequest"))
      request_params = +"#{params_prefix}SAMLRequest=#{saml_request}"
      params.each_pair do |key, value|
        request_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end
      raise SettingError.new "Invalid settings, idp_sso_service_url is not set!" if settings.idp_sso_service_url.nil? || settings.idp_sso_service_url.empty?
      @login_url = settings.idp_sso_service_url + request_params
    end

    # Creates the Get parameters for the request.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [Hash] Parameters
    def create_params(settings, params={})
      # The method expects :RelayState but sometimes we get 'RelayState' instead.
      # Based on the HashWithIndifferentAccess value in Rails we could experience
      # conflicts so this line will solve them.
      binding_redirect = settings.idp_sso_service_binding == Utils::BINDINGS[:redirect]
      relay_state = params[:RelayState] || params['RelayState']

      if relay_state.nil?
        params.delete(:RelayState)
        params.delete('RelayState')
      end

      request_doc = create_authentication_xml_doc(settings)
      request = request_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)

      Logging.debug "Created AuthnRequest: #{request}"

      request = deflate(request) if binding_redirect
      base64_request = encode(request)
      request_params = {"SAMLRequest" => base64_request}
      sp_signing_key = settings.get_sp_signing_key

      if binding_redirect && settings.security[:authn_requests_signed] && sp_signing_key
        params['SigAlg'] = settings.get_sp_signature_method
        url_string = RubySaml::Utils.build_query(
          type: 'SAMLRequest',
          data: base64_request,
          relay_state: relay_state,
          sig_alg: params['SigAlg']
        )
        sign_algorithm = RubySaml::XML.hash_algorithm(settings.get_sp_signature_method)
        signature = sp_signing_key.sign(sign_algorithm.new, url_string)
        params['Signature'] = encode(signature)
      end

      params.each_pair do |key, value|
        request_params[key] = value.to_s
      end

      request_params
    end

    # Creates the SAMLRequest String.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @return [String] The SAMLRequest String.
    def create_authentication_xml_doc(settings)
      noko = create_xml_document(settings)
      sign_document(noko, settings)
    end

    def create_xml_document(settings)
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      assign_uuid(settings)
      root_attributes = {
        'xmlns:samlp' => RubySaml::XML::NS_PROTOCOL,
        'xmlns:saml' => RubySaml::XML::NS_ASSERTION,
        'ID' => uuid,
        'IssueInstant' => time,
        'Version' => '2.0',
        'Destination' => settings.idp_sso_service_url,
        'IsPassive' => settings.passive,
        'ProtocolBinding' => settings.protocol_binding,
        'AttributeConsumingServiceIndex' => settings.attributes_index,
        'ForceAuthn' => settings.force_authn,
        'AssertionConsumerServiceURL' => settings.assertion_consumer_service_url
      }.compact.reject { |_, v| v.respond_to?(:empty?) && v.empty? }

      builder = Nokogiri::XML::Builder.new do |xml|
        xml['samlp'].AuthnRequest(root_attributes) do
          # Add Issuer element if sp_entity_id is present
          xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

          # Add Subject element if name_identifier_value_requested is present
          if settings.name_identifier_value_requested
            xml['saml'].Subject do
              nameid_attrs = {}
              nameid_attrs['Format'] = settings.name_identifier_format if settings.name_identifier_format
              xml['saml'].NameID(settings.name_identifier_value_requested, nameid_attrs)
              xml['saml'].SubjectConfirmation(Method: 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
            end
          end

          # Add NameIDPolicy element if name_identifier_format is present
          if settings.name_identifier_format
            xml['samlp'].NameIDPolicy(AllowCreate: 'true', Format: settings.name_identifier_format)
          end

          # Add RequestedAuthnContext if authn_context or authn_context_decl_ref is present
          if settings.authn_context || settings.authn_context_decl_ref
            comparison = settings.authn_context_comparison || 'exact'

            xml['samlp'].RequestedAuthnContext(Comparison: comparison) do
              Array(settings.authn_context).each do |authn_context_class_ref|
                xml['saml'].AuthnContextClassRef(authn_context_class_ref)
              end

              Array(settings.authn_context_decl_ref).each do |authn_context_decl_ref|
                xml['saml'].AuthnContextDeclRef(authn_context_decl_ref)
              end
            end
          end
        end
      end

      builder.doc
    end

    def sign_document(noko, settings)
      cert, private_key = settings.get_sp_signing_pair
      if settings.idp_sso_service_binding == Utils::BINDINGS[:post] && settings.security[:authn_requests_signed] && private_key && cert
        RubySaml::XML::DocumentSigner.sign_document!(noko, private_key, cert, settings.get_sp_signature_method, settings.get_sp_digest_method)
      else
        noko
      end
    end

    def assign_uuid(settings)
      @uuid ||= RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix) # rubocop:disable Naming/MemoizedInstanceVariableName
    end
  end
end

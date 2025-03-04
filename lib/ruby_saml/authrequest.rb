# frozen_string_literal: true

require "ruby_saml/logging"
require "ruby_saml/saml_message"
require "ruby_saml/utils"
require "ruby_saml/setting_error"

# Only supports SAML 2.0
module RubySaml

  # SAML2 Authentication. AuthNRequest (SSO SP initiated, Builder)
  #
  class Authrequest < SamlMessage

    # AuthNRequest ID
    attr_accessor :uuid
    alias_method :request_id, :uuid

    # Creates the AuthNRequest string.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [String] AuthNRequest string that includes the SAMLRequest
    #
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
    #
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
      request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values
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
        sign_algorithm = RubySaml::XML::Crypto.hash_algorithm(settings.get_sp_signature_method)
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
      document = create_xml_document(settings)
      sign_document(document, settings)
    end

    def create_xml_document(settings)
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      assign_uuid(settings)

      request_doc = Nokogiri::XML::Document.new

      root = Nokogiri::XML::Node.new("samlp:AuthnRequest", request_doc)
      request_doc.add_child(root)

      root["xmlns:samlp"] = "urn:oasis:names:tc:SAML:2.0:protocol"
      root["xmlns:saml"] = "urn:oasis:names:tc:SAML:2.0:assertion"
      root["ID"] = uuid
      root["IssueInstant"] = time
      root["Version"] = "2.0"
      root["Destination"] = settings.idp_sso_service_url unless settings.idp_sso_service_url.nil? || settings.idp_sso_service_url.empty?
      root["IsPassive"] = settings.passive unless settings.passive.nil?
      root["ProtocolBinding"] = settings.protocol_binding unless settings.protocol_binding.nil?
      root["AttributeConsumingServiceIndex"] = settings.attributes_index unless settings.attributes_index.nil?
      root["ForceAuthn"] = settings.force_authn unless settings.force_authn.nil?

      # Conditionally defined elements based on settings
      unless settings.assertion_consumer_service_url.nil?
        root["AssertionConsumerServiceURL"] = settings.assertion_consumer_service_url
      end

      unless settings.sp_entity_id.nil?
        issuer = Nokogiri::XML::Node.new("saml:Issuer", request_doc)
        issuer.content = settings.sp_entity_id
        root.add_child(issuer)
      end

      unless settings.name_identifier_value_requested.nil?
        subject = Nokogiri::XML::Node.new("saml:Subject", request_doc)
        root.add_child(subject)

        nameid = Nokogiri::XML::Node.new("saml:NameID", request_doc)
        nameid["Format"] = settings.name_identifier_format if settings.name_identifier_format
        nameid.content = settings.name_identifier_value_requested
        subject.add_child(nameid)

        subject_confirmation = Nokogiri::XML::Node.new("saml:SubjectConfirmation", request_doc)
        subject_confirmation["Method"] = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        subject.add_child(subject_confirmation)
      end

      unless settings.name_identifier_format.nil?
        name_id_policy = Nokogiri::XML::Node.new("samlp:NameIDPolicy", request_doc)
        # Might want to make AllowCreate a setting?
        name_id_policy["AllowCreate"] = "true"
        name_id_policy["Format"] = settings.name_identifier_format
        root.add_child(name_id_policy)
      end

      if settings.authn_context || settings.authn_context_decl_ref
        comparison = settings.authn_context_comparison.nil? ? 'exact' : settings.authn_context_comparison

        requested_context = Nokogiri::XML::Node.new("samlp:RequestedAuthnContext", request_doc)
        requested_context["Comparison"] = comparison
        root.add_child(requested_context)

        unless settings.authn_context.nil?
          authn_contexts_class_ref = settings.authn_context.is_a?(Array) ? settings.authn_context : [settings.authn_context]
          authn_contexts_class_ref.each do |authn_context_class_ref|
            class_ref = Nokogiri::XML::Node.new("saml:AuthnContextClassRef", request_doc)
            class_ref.content = authn_context_class_ref
            requested_context.add_child(class_ref)
          end
        end

        unless settings.authn_context_decl_ref.nil?
          authn_contexts_decl_refs = settings.authn_context_decl_ref.is_a?(Array) ? settings.authn_context_decl_ref : [settings.authn_context_decl_ref]
          authn_contexts_decl_refs.each do |authn_context_decl_ref|
            decl_ref = Nokogiri::XML::Node.new("saml:AuthnContextDeclRef", request_doc)
            decl_ref.content = authn_context_decl_ref
            requested_context.add_child(decl_ref)
          end
        end
      end

      request_doc
    end

    def sign_document(document, settings)
      cert, private_key = settings.get_sp_signing_pair
      if settings.idp_sso_service_binding == Utils::BINDINGS[:post] && settings.security[:authn_requests_signed] && private_key && cert
        RubySaml::XML::DocumentSigner.sign_document(document, private_key, cert, settings.get_sp_signature_method, settings.get_sp_digest_method, uuid)
      else
        document
      end
    end

    def assign_uuid(settings)
      @uuid ||= RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix) # rubocop:disable Naming/MemoizedInstanceVariableName
    end
  end
end

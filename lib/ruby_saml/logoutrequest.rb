# frozen_string_literal: true

require "ruby_saml/logging"
require "ruby_saml/saml_message"
require "ruby_saml/utils"
require "ruby_saml/setting_error"

# Only supports SAML 2.0
module RubySaml

  # SAML2 Logout Request (SLO SP initiated, Builder)
  #
  class Logoutrequest < SamlMessage

    # Logout Request ID
    attr_accessor :uuid
    alias_method :request_id, :uuid

    # Creates the Logout Request string.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [String] Logout Request string that includes the SAMLRequest
    #
    def create(settings, params={})
      assign_uuid(settings)
      params = create_params(settings, params)
      params_prefix = /\?/.match?(settings.idp_slo_service_url) ? '&' : '?'
      saml_request = CGI.escape(params.delete("SAMLRequest"))
      request_params = +"#{params_prefix}SAMLRequest=#{saml_request}"
      params.each_pair do |key, value|
        request_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end
      raise SettingError.new "Invalid settings, idp_slo_service_url is not set!" if settings.idp_slo_service_url.nil? or settings.idp_slo_service_url.empty?
      @logout_url = settings.idp_slo_service_url + request_params
    end

    # Creates the Get parameters for the logout request.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [Hash] Parameters
    #
    def create_params(settings, params={})
      # The method expects :RelayState but sometimes we get 'RelayState' instead.
      # Based on the HashWithIndifferentAccess value in Rails we could experience
      # conflicts so this line will solve them.
      binding_redirect = settings.idp_slo_service_binding == Utils::BINDINGS[:redirect]
      relay_state = params[:RelayState] || params['RelayState']

      if relay_state.nil?
        params.delete(:RelayState)
        params.delete('RelayState')
      end

      request_doc = create_logout_request_xml_doc(settings)
      request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

      request = +""
      request_doc.write(request)

      Logging.debug "Created SLO Logout Request: #{request}"

      request = deflate(request) if binding_redirect
      base64_request = encode(request)
      request_params = {"SAMLRequest" => base64_request}
      sp_signing_key = settings.get_sp_signing_key

      if binding_redirect && settings.security[:logout_requests_signed] && sp_signing_key
        params['SigAlg'] = settings.get_sp_signature_method
        url_string = RubySaml::Utils.build_query(
          type: 'SAMLRequest',
          data: base64_request,
          relay_state: relay_state,
          sig_alg: params['SigAlg']
        )
        sign_algorithm = RubySaml::XML::Crypto.hash_algorithm(settings.get_sp_signature_method)
        signature = settings.get_sp_signing_key.sign(sign_algorithm.new, url_string)
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
    #
    def create_logout_request_xml_doc(settings)
      document = create_xml_document(settings)
      sign_document(document, settings)
    end

    def create_xml_document(settings)
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      assign_uuid(settings)

      request_doc = RubySaml::XML::Document.new
      request_doc.uuid = uuid

      root = Nokogiri::XML::Element.new("samlp:LogoutRequest", request_doc)
      root["xmlns:samlp"] = "urn:oasis:names:tc:SAML:2.0:protocol"
      root["xmlns:saml"] = "urn:oasis:names:tc:SAML:2.0:assertion"
      root["ID"] = uuid
      root["IssueInstant"] = time
      root["Version"] = "2.0"
      root["Destination"] = settings.idp_slo_service_url unless settings.idp_slo_service_url.nil? or settings.idp_slo_service_url.empty?

      if settings.sp_entity_id
        issuer = Nokogiri::XML::Element.new("saml:Issuer", request_doc)
        issuer.content = settings.sp_entity_id
        root.add_child(issuer)
      end

      nameid = Nokogiri::XML::Element.new("saml:NameID", request_doc)
      if settings.name_identifier_value
        nameid["NameQualifier"] = settings.idp_name_qualifier if settings.idp_name_qualifier
        nameid["SPNameQualifier"] = settings.sp_name_qualifier if settings.sp_name_qualifier
        nameid["Format"] = settings.name_identifier_format if settings.name_identifier_format
        nameid.content = settings.name_identifier_value
      else
        # If no NameID is present in the settings we generate one
        nameid.content = RubySaml::Utils.uuid
        nameid["Format"] = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
      end
      root.add_child(nameid)

      if settings.sessionindex
        sessionindex = Nokogiri::XML::Element.new("samlp:SessionIndex", request_doc)
        sessionindex.content = settings.sessionindex
        root.add_child(sessionindex)
      end

      request_doc.add_child(root)
      request_doc
    end

    def sign_document(document, settings)
      # embed signature
      cert, private_key = settings.get_sp_signing_pair
      if settings.idp_slo_service_binding == Utils::BINDINGS[:post] && settings.security[:logout_requests_signed] && private_key && cert
        document.sign_document(private_key, cert, settings.get_sp_signature_method, settings.get_sp_digest_method)
      end

      document
    end

    def assign_uuid(settings)
      @uuid ||= RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix) # rubocop:disable Naming/MemoizedInstanceVariableName
    end
  end
end
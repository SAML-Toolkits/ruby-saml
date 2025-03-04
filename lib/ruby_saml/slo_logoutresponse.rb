# frozen_string_literal: true

require "ruby_saml/logging"
require "ruby_saml/saml_message"
require "ruby_saml/utils"
require "ruby_saml/setting_error"

# Only supports SAML 2.0
module RubySaml

  # SAML2 Logout Response (SLO SP initiated, Parser)
  #
  class SloLogoutresponse < SamlMessage

    # Logout Response ID
    attr_accessor :uuid
    alias_method :response_id, :uuid

    # Creates the Logout Response string.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
    # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [String] Logout Request string that includes the SAMLRequest
    #
    def create(settings, request_id = nil, logout_message = nil, params = {}, logout_status_code = nil)
      assign_uuid(settings)
      params = create_params(settings, request_id, logout_message, params, logout_status_code)
      params_prefix = /\?/.match?(settings.idp_slo_service_url) ? '&' : '?'
      url = settings.idp_slo_response_service_url || settings.idp_slo_service_url
      saml_response = CGI.escape(params.delete("SAMLResponse"))
      response_params = +"#{params_prefix}SAMLResponse=#{saml_response}"
      params.each_pair do |key, value|
        response_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end

      raise SettingError.new "Invalid settings, idp_slo_service_url is not set!" if url.nil? || url.empty?
      @logout_url = url + response_params
    end

    # Creates the Get parameters for the logout response.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
    # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [Hash] Parameters
    #
    def create_params(settings, request_id = nil, logout_message = nil, params = {}, logout_status_code = nil)
      # The method expects :RelayState but sometimes we get 'RelayState' instead.
      # Based on the HashWithIndifferentAccess value in Rails we could experience
      # conflicts so this line will solve them.
      binding_redirect = settings.idp_slo_service_binding == Utils::BINDINGS[:redirect]
      relay_state = params[:RelayState] || params['RelayState']

      if relay_state.nil?
        params.delete(:RelayState)
        params.delete('RelayState')
      end

      response_doc = create_logout_response_xml_doc(settings, request_id, logout_message, logout_status_code)
      response_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values
      response = response_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)

      Logging.debug "Created SLO Logout Response: #{response}"

      response = deflate(response) if binding_redirect
      base64_response = encode(response)
      response_params = {"SAMLResponse" => base64_response}
      sp_signing_key = settings.get_sp_signing_key

      if binding_redirect && settings.security[:logout_responses_signed] && sp_signing_key
        params['SigAlg'] = settings.get_sp_signature_method
        url_string = RubySaml::Utils.build_query(
          type: 'SAMLResponse',
          data: base64_response,
          relay_state: relay_state,
          sig_alg: params['SigAlg']
        )
        sign_algorithm = RubySaml::XML::Crypto.hash_algorithm(settings.get_sp_signature_method)
        signature = sp_signing_key.sign(sign_algorithm.new, url_string)
        params['Signature'] = encode(signature)
      end

      params.each_pair do |key, value|
        response_params[key] = value.to_s
      end

      response_params
    end

    # Creates the SAMLResponse String.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
    # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [String] The SAMLResponse String.
    #
    def create_logout_response_xml_doc(settings, request_id = nil, logout_message = nil, logout_status_code = nil)
      document = create_xml_document(settings, request_id, logout_message, logout_status_code)
      sign_document(document, settings)
    end

    def create_xml_document(settings, request_id = nil, logout_message = nil, status_code = nil)
      time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
      assign_uuid(settings)

      response_doc = Nokogiri::XML::Document.new

      destination = settings.idp_slo_response_service_url || settings.idp_slo_service_url

      root = Nokogiri::XML::Node.new('samlp:LogoutResponse', response_doc)
      response_doc.add_child(root)

      # Set namespaces
      root['xmlns:samlp'] = 'urn:oasis:names:tc:SAML:2.0:protocol'
      root['xmlns:saml'] = 'urn:oasis:names:tc:SAML:2.0:assertion'

      # Set attributes
      root['ID'] = uuid
      root['IssueInstant'] = time
      root['Version'] = '2.0'
      root['InResponseTo'] = request_id unless request_id.nil?
      root['Destination'] = destination unless destination.nil? or destination.empty?

      unless settings.sp_entity_id.nil?
        issuer = Nokogiri::XML::Node.new('saml:Issuer', response_doc)
        issuer.content = settings.sp_entity_id
        root.add_child(issuer)
      end

      # add status
      status = Nokogiri::XML::Node.new('samlp:Status', response_doc)
      root.add_child(status)

      # status code
      status_code ||= 'urn:oasis:names:tc:SAML:2.0:status:Success'
      status_code_elem = Nokogiri::XML::Node.new('samlp:StatusCode', response_doc)
      status_code_elem['Value'] = status_code
      status.add_child(status_code_elem)

      # status message
      logout_message ||= 'Successfully Signed Out'
      status_message = Nokogiri::XML::Node.new('samlp:StatusMessage', response_doc)
      status_message.content = logout_message
      status.add_child(status_message)

      response_doc
    end

    def sign_document(document, settings)
      cert, private_key = settings.get_sp_signing_pair
      if settings.idp_slo_service_binding == Utils::BINDINGS[:post] && private_key && cert
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

# frozen_string_literal: true

require "ruby_saml/logging"
require "ruby_saml/saml_message"
require "ruby_saml/utils"
require "ruby_saml/setting_error"

module RubySaml
  # SAML2 Logout Response (SLO SP initiated, Parser)
  class SloLogoutresponse < SamlMessage

    # Logout Response ID
    attr_accessor :uuid
    alias_method :response_id, :uuid

    # Creates the Logout Response string.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
    # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
    # @param params [Hash] Some extra parameters to be added in the GET for example, the RelayState
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [String] Logout Request string that includes the SAMLRequest
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
    # @param params [Hash] Some extra parameters to be added in the GET for example, the RelayState
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [Hash] Parameters
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
      response = response_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)

      Logging.debug "Created SLO Logout Response: #{response}"

      base64_response = RubySaml::XML::Decoder.encode_message(response, compress: binding_redirect)
      response_params = { 'SAMLResponse' => base64_response }
      sp_signing_key = settings.get_sp_signing_key

      if binding_redirect && settings.security[:logout_responses_signed] && sp_signing_key
        params['SigAlg'] = settings.get_sp_signature_method
        url_string = RubySaml::Utils.build_query(
          type: 'SAMLResponse',
          data: base64_response,
          relay_state: relay_state,
          sig_alg: params['SigAlg']
        )
        sign_algorithm = RubySaml::XML.hash_algorithm(settings.get_sp_signature_method)
        signature = sp_signing_key.sign(sign_algorithm.new, url_string)
        params['Signature'] = Base64.strict_encode64(signature)
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
    def create_logout_response_xml_doc(settings, request_id = nil, logout_message = nil, logout_status_code = nil)
      noko = create_xml_document(settings, request_id, logout_message, logout_status_code)
      sign_document(noko, settings)
    end

    def create_xml_document(settings, request_id = nil, logout_message = nil, status_code = nil)
      time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
      assign_uuid(settings)

      root_attributes = {
        'xmlns:samlp' => RubySaml::XML::NS_PROTOCOL,
        'xmlns:saml' => RubySaml::XML::NS_ASSERTION,
        'ID' => uuid,
        'IssueInstant' => time,
        'Version' => '2.0',
        'InResponseTo' => request_id,
        'Destination' => settings.idp_slo_response_service_url || settings.idp_slo_service_url
      }.compact.reject { |_, v| v.respond_to?(:empty?) && v.empty? }

      # Default values if not provided
      status_code ||= 'urn:oasis:names:tc:SAML:2.0:status:Success'
      logout_message ||= 'Successfully Signed Out'

      builder = Nokogiri::XML::Builder.new do |xml|
        xml['samlp'].LogoutResponse(root_attributes) do
          # Add Issuer element if sp_entity_id is present
          xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

          # Add Status section
          xml['samlp'].Status do
            xml['samlp'].StatusCode(Value: status_code)
            xml['samlp'].StatusMessage(logout_message)
          end
        end
      end

      builder.doc
    end

    def sign_document(noko, settings)
      cert, private_key = settings.get_sp_signing_pair
      if settings.idp_slo_service_binding == Utils::BINDINGS[:post] && private_key && cert
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

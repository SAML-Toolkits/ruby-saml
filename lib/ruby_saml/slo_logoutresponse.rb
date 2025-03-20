# frozen_string_literal: true

require "ruby_saml/logging"
require "ruby_saml/saml_message"
require "ruby_saml/utils"
require "ruby_saml/setting_error"

module RubySaml
  # SAML2 Logout Response (SLO SP initiated)
  #
  # Shim class that delegates to RubySaml::Sp::Builders::LogoutResponse
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
    def create(settings, request_id = nil, logout_message = nil, params = {}, logout_status_code = nil)
      create_builder(settings, request_id, logout_message, params, logout_status_code)
      @logout_url = builder.url
    end

    # Creates the Get parameters for the logout response.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
    # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [Hash] Parameters
    def create_params(settings, request_id = nil, logout_message = nil, params = {}, logout_status_code = nil)
      create_builder(settings, request_id, logout_message, params, logout_status_code)
      is_redirect = settings.idp_slo_service_binding == Utils::BINDINGS[:redirect]

      # Log the response
      response_doc = builder.send(:build_xml_document)
      response = response_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
      Logging.debug "Created SLO Logout Response: #{response}"

      # Get payload parameters
      builder.send(:build_payload, is_redirect)
    end

    def create_logout_response_xml_doc(settings, request_id = nil, logout_message = nil, status_code = nil)
      create_builder(settings, request_id, logout_message, {}, status_code)
      noko = builder.send(:build_xml_document)
      sign_document(noko) # TODO: unless redirect
    end

    def create_xml_document(settings, request_id = nil, logout_message = nil, status_code = nil)
      create_builder(settings, request_id, logout_message, {}, status_code)
      builder.send(:build_xml_document)
    end

    def sign_document(noko, _settings = nil)
      builder.send(:sign_xml_document!, noko)
    end

    private

    attr_reader :builder

    def create_builder(settings, request_id = nil, logout_message = nil, params = {}, logout_status_code = nil)
      @uuid ||= RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix)
      @builder ||= RubySaml::Sp::Builders::LogoutResponse.new(
        settings,
        id: @uuid,
        in_response_to: request_id,
        params: params,
        status_code: logout_status_code,
        status_message: logout_message
      )
    end
  end
end

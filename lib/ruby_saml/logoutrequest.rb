# frozen_string_literal: true

require "ruby_saml/logging"
require "ruby_saml/saml_message"
require "ruby_saml/utils"
require "ruby_saml/setting_error"

module RubySaml
  # SAML2 Logout Request (SLO SP initiated)
  #
  # Shim class that delegates to RubySaml::Sp::Builders::LogoutRequest
  class Logoutrequest < SamlMessage
    # Logout Request ID
    attr_accessor :uuid
    alias_method :request_id, :uuid

    # Creates the Logout Request string.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [String] Logout Request string that includes the SAMLRequest
    def create(settings, params = {})
      create_builder(settings, params)
      @logout_url = builder.url
    end

    # Creates the Get parameters for the logout request.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [Hash] Parameters
    def create_params(settings, params = {})
      create_builder(settings, params)

      request_doc = builder.send(:build_xml_document)
      request = request_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
      Logging.debug "Created SLO Logout Request: #{request}"

      is_redirect = settings.idp_slo_service_binding == Utils::BINDINGS[:redirect]
      builder.send(:build_payload, is_redirect)
    end

    def create_logout_request_xml_doc(settings)
      create_builder(settings)
      noko = builder.send(:build_xml_document)
      sign_document(noko)
      # is_redirect = settings.idp_slo_service_binding == Utils::BINDINGS[:redirect]
      # sign_document(noko) unless is_redirect
      # noko
    end

    def create_xml_document(settings)
      create_builder(settings)
      builder.send(:build_xml_document)
    end

    def sign_document(noko, _settings = nil)
      builder.send(:sign_xml_document!, noko)
    end

    private

    attr_reader :builder

    def create_builder(settings, params = {})
      @uuid ||= RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix)
      @builder ||= RubySaml::Sp::Builders::LogoutRequest.new(
        settings,
        id: @uuid,
        params: params
      )
    end
  end
end

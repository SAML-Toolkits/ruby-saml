# frozen_string_literal: true

require "ruby_saml/logging"
require "ruby_saml/saml_message"
require "ruby_saml/utils"
require "ruby_saml/setting_error"

module RubySaml
  # SAML2 Authentication. AuthnRequest (SSO SP initiated)
  #
  # Shim class that delegates to RubySaml::Sp::Builders::AuthnRequest
  class Authrequest < SamlMessage
    # AuthnRequest ID
    attr_accessor :uuid
    alias_method :request_id, :uuid

    # Creates the AuthnRequest string.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [String] AuthnRequest string that includes the SAMLRequest
    def create(settings, params = {})
      create_builder(settings, params)
      @login_url = builder.url
    end

    # Creates the Get parameters for the request.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [Hash] Parameters
    def create_params(settings, params={})
      create_builder(settings, params)
      is_redirect = settings.idp_sso_service_binding == Utils::BINDINGS[:redirect]

      # Log the request
      request_doc = builder.send(:build_xml_document)
      request = request_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
      Logging.debug "Created AuthnRequest: #{request}"

      # Get payload parameters
      builder.send(:build_payload, is_redirect)
    end

    # Creates the SAMLRequest String.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @return [String] The SAMLRequest String.
    def create_authentication_xml_doc(settings, params = nil)
      create_builder(settings, params)
      builder.send(:build_xml_document)
    end

    def sign_document(noko, _settings = nil)
      builder.send(:sign_xml_document!, noko)
    end

    private

    attr_reader :builder

    def create_builder(settings, params = {})
      @uuid ||= RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix)
      @builder ||= RubySaml::Sp::Builders::AuthnRequest.new(
        settings,
        id: @uuid,
        params: params
      )
    end
  end
end

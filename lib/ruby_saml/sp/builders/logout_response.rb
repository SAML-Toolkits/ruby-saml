# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML2.0 Logout Response (SLO SP-initiated)
      #
      # Creates a SAML LogoutResponse for Single Logout.
      # The XML message is created and embedded into the HTTP-GET or HTTP-POST response
      # according to the SAML Binding used.
      class LogoutResponse < MessageBuilder
        DEFAULT_STATUS_CODE = 'urn:oasis:names:tc:SAML:2.0:status:Success'
        DEFAULT_STATUS_MESSAGE = 'Successfully Signed Out'

        # Creates a new LogoutResponse builder instance
        # @param settings [RubySaml::Settings] Toolkit settings
        # @param in_response_to [String] The ID of the LogoutRequest this response is for
        # @param id [String|nil] ID for the response (if nil, one will be generated)
        # @param relay_state [String|nil] RelayState parameter
        # @param params [Hash|nil] Additional parameters
        # @param status_code [String|nil] Status code for the response (default: Success)
        # @param status_message [String|nil] Status message for the response (default: "Successfully Signed Out")
        def initialize(settings, in_response_to:, id: nil, relay_state: nil, params: nil, status_code: nil, status_message: nil)
          super(settings, id: id, relay_state: relay_state, params: nil)
          @in_response_to = in_response_to
          @status_code = status_code || DEFAULT_STATUS_CODE
          @status_message = status_message || DEFAULT_STATUS_MESSAGE
        end

        private

        attr_reader :in_response_to,
                    :status_code,
                    :status_message

        # Returns the message type for the response
        # @return [String] The message type
        def message_type
          'SAMLResponse'
        end

        # Determine the binding type from settings
        # @return [String] The binding type
        def binding_type
          settings.idp_slo_service_binding
        end

        # Get the service URL from settings with validation
        # @return [String] The IdP SLO URL for the response
        # @raise [SettingError] if the URL is not set
        def service_url
          url = settings.idp_slo_response_service_url || settings.idp_slo_service_url
          raise SettingError.new "Invalid settings, IdP SLO service URL is not set!" if url.nil? || url.empty?
          url
        end

        # Determines if the message should be signed
        # @return [Boolean] True if the message should be signed
        def sign?
          settings.security[:logout_responses_signed]
        end

        # Build the logout response XML document
        # @return [Nokogiri::XML::Document] A XML document containing the response
        def build_xml_document
          Nokogiri::XML::Builder.new do |xml|
            xml['samlp'].LogoutResponse(xml_root_attributes) do
              xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

              xml['samlp'].Status do
                xml['samlp'].StatusCode(Value: status_code)
                xml['samlp'].StatusMessage(status_message)
              end
            end
          end.doc
        end

        # Returns the attributes for the SAML root element
        # @return [Hash] A hash of attributes for the SAML root element
        def xml_root_attributes
          hash = super
          hash['InResponseTo'] = in_response_to
          compact_blank!(hash)
        end
      end
    end
  end
end

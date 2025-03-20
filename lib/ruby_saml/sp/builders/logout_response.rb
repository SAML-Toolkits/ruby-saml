# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML LogoutResponse builder (SLO, IdP-initiated)
      class LogoutResponse < MessageBuilder
        DEFAULT_STATUS_CODE = 'urn:oasis:names:tc:SAML:2.0:status:Success'
        DEFAULT_STATUS_MESSAGE = 'Successfully Signed Out'

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

        def message_type
          'SAMLResponse'
        end

        # Determine the binding type from settings
        def binding_type
          settings.idp_slo_service_binding
        end

        # Get the service URL from settings with validation
        def service_url
          url = settings.idp_slo_response_service_url || settings.idp_slo_service_url
          raise SettingError.new "Invalid settings, IdP SLO service URL is not set!" if url.nil? || url.empty?
          url
        end

        def sign?
          settings.security[:logout_responses_signed]
        end

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

        def xml_root_attributes
          hash = super
          hash['InResponseTo'] = in_response_to
          compact_blank!(hash)
        end
      end
    end
  end
end

# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML LogoutResponse builder (SLO, IdP-initiated)
      class LogoutResponse < MessageBuilder
        alias_method :response_id, :uuid

        private

        def message_flow
          :slo
        end

        # Build the XML document
        def create_xml(settings, request_id: nil, status_message: nil, status_code: nil)
          time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

          # Default values if not provided
          status_code ||= 'urn:oasis:names:tc:SAML:2.0:status:Success'
          status_message ||= 'Successfully Signed Out'

          root_attributes = {
            'xmlns:samlp' => RubySaml::XML::NS_PROTOCOL,
            'xmlns:saml' => RubySaml::XML::NS_ASSERTION,
            'ID' => uuid,
            'IssueInstant' => time,
            'Version' => '2.0',
            'InResponseTo' => request_id,
            'Destination' => service_url(settings, :slo_response)
          }.compact

          build_message(settings, 'LogoutResponse', root_attributes, :logout_responses_signed) do |xml|
            # Add Issuer
            xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

            # Add Status
            xml['samlp'].Status do
              xml['samlp'].StatusCode(Value: status_code)
              xml['samlp'].StatusMessage(status_message)
            end
          end
        end
      end
    end
  end
end

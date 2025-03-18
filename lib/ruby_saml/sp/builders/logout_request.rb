# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML LogoutRequest builder (SLO, SP-initiated)
      class LogoutRequest < MessageBuilder
        alias_method :request_id, :uuid

        def create(settings, old_params = {}, relay_state: nil)
          super
        end

        private

        def message_flow
          :slo
        end

        # Build the XML document
        def create_xml(settings)
          time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

          root_attributes = {
            'xmlns:samlp' => RubySaml::XML::NS_PROTOCOL,
            'xmlns:saml' => RubySaml::XML::NS_ASSERTION,
            'ID' => uuid,
            'IssueInstant' => time,
            'Version' => '2.0',
            'Destination' => settings.idp_slo_service_url
          }

          build_message(settings, 'LogoutRequest', root_attributes, :logout_requests_signed) do |xml|
            # Add Issuer
            xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

            # Add NameID
            if settings.name_identifier_value
              nameid_attrs = {
                'NameQualifier' => settings.idp_name_qualifier,
                'SPNameQualifier' => settings.sp_name_qualifier,
                'Format' => settings.name_identifier_format
              }
              xml['saml'].NameID(settings.name_identifier_value, clean_attributes(nameid_attrs))
            else
              xml['saml'].NameID(RubySaml::Utils.uuid,
                                 'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
            end

            # Add SessionIndex if provided
            xml['samlp'].SessionIndex(settings.sessionindex) if settings.sessionindex
          end
        end
      end
    end
  end
end

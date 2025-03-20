# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML AuthnRequest builder (SSO, SP-initiated)
      class AuthnRequest < MessageBuilder

        private

        def message_type
          'SAMLRequest'
        end

        # Determine the binding type from settings
        def binding_type
          settings.idp_sso_service_binding
        end

        # Get the service URL from settings based on type
        def service_url
          url = settings.idp_sso_service_url
          raise SettingError.new "Invalid settings, idp_sso_service_url is not set!" if url.nil? || url.empty?
          url
        end

        def sign?
          settings.security[:authn_requests_signed]
        end

        # TODO: Re-add comments
        def build_xml_document
          Nokogiri::XML::Builder.new do |xml|
            xml['samlp'].AuthnRequest(compact_blank(xml_root_attributes)) do

              # Add Issuer element if sp_entity_id is present
              xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

              if settings.name_identifier_value_requested
                xml['saml'].Subject do
                  xml['saml'].NameID(settings.name_identifier_value_requested, xml_nameid_attributes)
                  xml['saml'].SubjectConfirmation(Method: 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
                end
              end

              if settings.name_identifier_format
                xml['samlp'].NameIDPolicy(AllowCreate: 'true', Format: settings.name_identifier_format)
              end

              if settings.authn_context || settings.authn_context_decl_ref
                comparison = settings.authn_context_comparison || 'exact'

                xml['samlp'].RequestedAuthnContext(Comparison: comparison) do
                  Array(settings.authn_context).each do |authn_context_class_ref|
                    xml['saml'].AuthnContextClassRef(authn_context_class_ref)
                  end

                  Array(settings.authn_context_decl_ref).each do |authn_context_decl_ref|
                    xml['saml'].AuthnContextDeclRef(authn_context_decl_ref)
                  end
                end
              end
            end
          end.doc
        end

        def xml_root_attributes
          hash = super
          hash['IsPassive'] = settings.passive
          hash['ProtocolBinding'] = settings.protocol_binding
          hash['AttributeConsumingServiceIndex'] = settings.attributes_index
          hash['ForceAuthn'] = settings.force_authn
          hash['AssertionConsumerServiceURL'] = settings.assertion_consumer_service_url
          compact_blank!(hash)
        end

        def xml_nameid_attributes
          compact_blank!('Format' => settings.name_identifier_format)
        end
      end
    end
  end
end

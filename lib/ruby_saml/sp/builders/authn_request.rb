# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML AuthnRequest builder (SSO, SP-initiated)
      module AuthnRequest
        extend MessageBuilder
        extend self

        def create(settings, old_params = {}, uuid: nil, relay_state: nil)
          super
        end

        private

        # Determine the binding type from settings
        def binding_type(settings)
          settings.idp_sso_service_binding
        end

        # Get the service URL from settings based on type
        def service_url(settings)
          settings.idp_sso_service_url
        end

        # Build the XML document
        def create_xml(settings, uuid: nil)
          time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

          root_attributes = {
            'xmlns:samlp' => RubySaml::XML::NS_PROTOCOL,
            'xmlns:saml' => RubySaml::XML::NS_ASSERTION,
            'ID' => uuid,
            'IssueInstant' => time,
            'Version' => '2.0',
            'Destination' => settings.idp_sso_service_url,
            'IsPassive' => settings.passive,
            'ProtocolBinding' => settings.protocol_binding,
            'AttributeConsumingServiceIndex' => settings.attributes_index,
            'ForceAuthn' => settings.force_authn,
            'AssertionConsumerServiceURL' => settings.assertion_consumer_service_url
          }

          build_message(settings, 'AuthnRequest', root_attributes, :authn_requests_signed) do |xml|
            # Add Issuer
            xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

            # Add Subject if requested
            if settings.name_identifier_value_requested
              xml['saml'].Subject do
                nameid_attrs = {}
                nameid_attrs['Format'] = settings.name_identifier_format if settings.name_identifier_format
                xml['saml'].NameID(settings.name_identifier_value_requested, nameid_attrs)
                xml['saml'].SubjectConfirmation(Method: 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
              end
            end

            # Add NameIDPolicy if format is specified
            if settings.name_identifier_format
              xml['samlp'].NameIDPolicy(AllowCreate: 'true', Format: settings.name_identifier_format)
            end

            # Add RequestedAuthnContext if needed
            if settings.authn_context || settings.authn_context_decl_ref
              comparison = settings.authn_context_comparison || 'exact'

              xml['samlp'].RequestedAuthnContext(Comparison: comparison) do
                Array(settings.authn_context).each do |context_class|
                  xml['saml'].AuthnContextClassRef(context_class)
                end

                Array(settings.authn_context_decl_ref).each do |decl_ref|
                  xml['saml'].AuthnContextDeclRef(decl_ref)
                end
              end
            end
          end
        end
      end
    end
  end
end

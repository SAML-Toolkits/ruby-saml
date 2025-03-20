# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML2.0 Authentication Request (SSO SP-initiated, Builder)
      #
      # Creates a SAML AuthnRequest for Service Provider initiated Authentication.
      # The XML message is created and embedded into the HTTP-GET or HTTP-POST request
      # according to the SAML Binding used.
      class AuthnRequest < MessageBuilder

        private

        # Returns the message type for the request
        # @return [String] The message type
        def message_type
          'SAMLRequest'
        end

        # Determine the binding type from settings
        # @return [String] The binding type
        def binding_type
          settings.idp_sso_service_binding
        end

        # Get the service URL from settings based on type
        # @return [String] The IdP SSO URL
        # @raise [SettingError] if the URL is not set
        def service_url
          url = settings.idp_sso_service_url
          raise SettingError.new "Invalid settings, idp_sso_service_url is not set!" if url.nil? || url.empty?
          url
        end

        # Determines if the message should be signed
        # @return [Boolean] True if the message should be signed
        def sign?
          settings.security[:authn_requests_signed]
        end

        # Build the authentication request XML document
        # @return [Nokogiri::XML::Document] A XML document containing the request
        def build_xml_document
          Nokogiri::XML::Builder.new do |xml|
            xml['samlp'].AuthnRequest(compact_blank(xml_root_attributes)) do

              # Add Issuer element if sp_entity_id is present
              xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

              # Add Subject element if name_identifier_value_requested is present
              if settings.name_identifier_value_requested
                xml['saml'].Subject do
                  xml['saml'].NameID(settings.name_identifier_value_requested, xml_nameid_attributes)
                  xml['saml'].SubjectConfirmation(Method: 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
                end
              end

              # Add NameIDPolicy element if name_identifier_format is present
              if settings.name_identifier_format
                xml['samlp'].NameIDPolicy(AllowCreate: 'true', Format: settings.name_identifier_format)
              end

              # Add RequestedAuthnContext if authn_context or authn_context_decl_ref is present
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

        # Returns the attributes for the SAML root element
        # @return [Hash] A hash of attributes for the SAML root element
        def xml_root_attributes
          hash = super
          hash['IsPassive'] = settings.passive
          hash['ProtocolBinding'] = settings.protocol_binding
          hash['AttributeConsumingServiceIndex'] = settings.attributes_index
          hash['ForceAuthn'] = settings.force_authn
          hash['AssertionConsumerServiceURL'] = settings.assertion_consumer_service_url
          compact_blank!(hash)
        end

        # Returns the attributes for the NameID element
        # @return [Hash] A hash of attributes for the NameID element
        def xml_nameid_attributes
          compact_blank!('Format' => settings.name_identifier_format)
        end
      end
    end
  end
end

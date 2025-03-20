# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML2.0 Logout Request (SLO SP-initiated, Builder)
      #
      # Creates a SAML LogoutRequest for Service Provider initiated Single Logout.
      # The XML message is created and embedded into the HTTP-GET or HTTP-POST request
      # according to the SAML Binding used.
      class LogoutRequest < MessageBuilder

        private

        # Returns the message type for the request
        # @return [String] The message type
        def message_type
          'SAMLRequest'
        end

        # Determine the binding type from settings
        # @return [String] The binding type
        def binding_type
          settings.idp_slo_service_binding
        end

        # Get the service URL from settings based on type with validation
        # @return [String] The IdP SLO URL
        # @raise [SettingError] if the URL is not set
        def service_url
          url = settings.idp_slo_service_url
          raise SettingError.new "Invalid settings, idp_slo_service_url is not set!" if url.nil? || url.empty?
          url
        end

        # Determines if the message should be signed
        # @return [Boolean] True if the message should be signed
        def sign?
          settings.security[:logout_requests_signed]
        end

        # Build the logout request XML document
        # @return [Nokogiri::XML::Document] A XML document containing the request
        def build_xml_document
          Nokogiri::XML::Builder.new do |xml|
            xml['samlp'].LogoutRequest(compact_blank(xml_root_attributes)) do
              xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

              if settings.name_identifier_value
                xml['saml'].NameID(settings.name_identifier_value, xml_nameid_attributes)
              else
                xml['saml'].NameID(RubySaml::Utils.generate_uuid,
                                   'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
              end

              xml['samlp'].SessionIndex(settings.sessionindex) if settings.sessionindex
            end
          end.doc
        end

        # Returns the attributes for the NameID element
        # @return [Hash] A hash of attributes for the NameID element
        def xml_nameid_attributes
          compact_blank!(
            'NameQualifier' => settings.idp_name_qualifier,
            'SPNameQualifier' => settings.sp_name_qualifier,
            'Format' => settings.name_identifier_format
          )
        end
      end
    end
  end
end

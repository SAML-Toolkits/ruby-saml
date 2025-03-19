# frozen_string_literal: true

require "uri"
require "ruby_saml/logging"
require "ruby_saml/utils"

module RubySaml
  # SAML2 Metadata. XML Metadata Builder
  class Metadata
    # Return SP metadata based on the settings.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param pretty_print [Boolean] Pretty print or not the response
    #   (No pretty print if you gonna validate the signature)
    # @param valid_until [DateTime] Metadata's valid time
    # @param cache_duration [Integer] Duration of the cache in seconds
    # @return [String] XML Metadata of the Service Provider
    def generate(settings, pretty_print = false, valid_until = nil, cache_duration = nil)
      builder = Nokogiri::XML::Builder.new(encoding: 'UTF-8') do |xml|
        root_attributes = {
          'xmlns:md' => RubySaml::XML::NS_METADATA,
          'xmlns:ds' => RubySaml::XML::DSIG,
          'ID' => RubySaml::Utils.uuid,
          'entityID' => settings.sp_entity_id
        }

        if valid_until
          root_attributes['validUntil'] = valid_until.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        end

        if cache_duration
          root_attributes['cacheDuration'] = "PT#{cache_duration}S"
        end

        # Add saml namespace if attribute consuming service is configured
        if settings.attribute_consuming_service.configured?
          root_attributes['xmlns:saml'] = 'urn:oasis:names:tc:SAML:2.0:assertion'
        end

        xml['md'].EntityDescriptor(root_attributes) do
          sp_sso_attributes = {
            'protocolSupportEnumeration' => 'urn:oasis:names:tc:SAML:2.0:protocol',
            'AuthnRequestsSigned' => settings.security[:authn_requests_signed] ? 'true' : 'false',
            'WantAssertionsSigned' => settings.security[:want_assertions_signed] ? 'true' : 'false'
          }

          xml['md'].SPSSODescriptor(sp_sso_attributes) do
            # Add certificates
            certs = settings.get_sp_certs
            certs[:signing].each do |cert, _|
              add_certificate_element(xml, cert, :signing) if cert
            end
            if settings.security[:want_assertions_encrypted]
              certs[:encryption].each do |cert, _|
                add_certificate_element(xml, cert, :encryption) if cert
              end
            end

            # Add SingleLogoutService if configured
            if settings.single_logout_service_url
              xml['md'].SingleLogoutService(
                'Binding' => settings.single_logout_service_binding,
                'Location' => settings.single_logout_service_url,
                'ResponseLocation' => settings.single_logout_service_url
              )
            end

            # Add NameIDFormat if configured
            if settings.name_identifier_format
              xml['md'].NameIDFormat(settings.name_identifier_format)
            end

            # Add AssertionConsumerService if configured
            if settings.assertion_consumer_service_url
              xml['md'].AssertionConsumerService(
                'Binding' => settings.assertion_consumer_service_binding,
                'Location' => settings.assertion_consumer_service_url,
                'isDefault' => 'true',
                'index' => '0'
              )
            end

            # Add AttributeConsumingService if configured
            if settings.attribute_consuming_service.configured?
              xml['md'].AttributeConsumingService(
                'isDefault' => 'true',
                'index' => settings.attribute_consuming_service.index
              ) do
                xml['md'].ServiceName(
                  settings.attribute_consuming_service.name,
                  'xml:lang' => 'en'
                )

                settings.attribute_consuming_service.attributes.each do |attribute|
                  attr_options = {
                    'NameFormat' => attribute[:name_format],
                    'Name' => attribute[:name],
                    'FriendlyName' => attribute[:friendly_name],
                    'isRequired' => attribute[:is_required] ? 'true' : 'false'
                  }

                  xml['md'].RequestedAttribute(attr_options) do
                    # Add AttributeValues if present
                    unless attribute[:attribute_value].nil?
                      Array(attribute[:attribute_value]).each do |value|
                        xml['saml'].AttributeValue(value.to_s)
                      end
                    end
                  end
                end
              end
            end
          end

          # Add any extra elements (can be overridden in subclass)
          add_extras(xml, settings)
        end
      end

      # Get the XML document
      meta_doc = builder.doc
      embed_signature(meta_doc, settings)
      output_xml(meta_doc, pretty_print)
    end

    protected

    # can be overridden in subclass
    def add_extras(_xml, _settings)
      # Do nothing by default
    end

    def embed_signature(meta_doc, settings)
      return unless settings.security[:metadata_signed]

      cert, private_key = settings.get_sp_signing_pair
      return unless private_key && cert

      RubySaml::XML::DocumentSigner.sign_document!(meta_doc, private_key, cert, settings.get_sp_signature_method, settings.get_sp_digest_method)
    end

    # pretty print the XML so IdP administrators can easily see what the SP supports
    def output_xml(meta_doc, pretty_print)
      if pretty_print
        meta_doc.to_xml(indent: 1)
      else
        meta_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
      end
    end

    private

    def add_certificate_element(xml, cert, use)
      cert_text = Base64.encode64(cert.to_der).delete("\n")
      xml['md'].KeyDescriptor('use' => use.to_s) do
        xml['ds'].KeyInfo do
          xml['ds'].X509Data do
            xml['ds'].X509Certificate(cert_text)
          end
        end
      end
    end
  end
end

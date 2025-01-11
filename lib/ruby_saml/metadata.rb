# frozen_string_literal: true

require "uri"

require "ruby_saml/logging"
require "ruby_saml/utils"

# Only supports SAML 2.0
module RubySaml

  # SAML2 Metadata. XML Metadata Builder
  #
  class Metadata

    # Return SP metadata based on the settings.
    # @param settings [RubySaml::Settings|nil] Toolkit settings
    # @param pretty_print [Boolean] Pretty print or not the response
    #                               (No pretty print if you gonna validate the signature)
    # @param valid_until [DateTime] Metadata's valid time
    # @param cache_duration [Integer] Duration of the cache in seconds
    # @return [String] XML Metadata of the Service Provider
    #
    def generate(settings, pretty_print=false, valid_until=nil, cache_duration=nil)
      meta_doc = Nokogiri::XML::Document.new
      add_xml_declaration(meta_doc)
      root = add_root_element(meta_doc, settings, valid_until, cache_duration)
      sp_sso = add_sp_sso_element(root, settings)
      add_sp_certificates(sp_sso, settings)
      add_sp_service_elements(sp_sso, settings)
      add_extras(root, settings)
      embed_signature(meta_doc, settings)
      output_xml(meta_doc, pretty_print)
    end

    protected

    def add_xml_declaration(meta_doc)
      meta_doc.create_internal_subset('xml', nil, nil)
    end

    def add_root_element(meta_doc, settings, valid_until, cache_duration)
      namespaces = {
        "xmlns:md" => "urn:oasis:names:tc:SAML:2.0:metadata"
      }

      if settings.attribute_consuming_service.configured?
        namespaces["xmlns:saml"] = "urn:oasis:names:tc:SAML:2.0:assertion"
      end

      root = Nokogiri::XML::Node.new("md:EntityDescriptor", meta_doc)
      root["ID"] = RubySaml::Utils.uuid
      root["entityID"] = settings.sp_entity_id if settings.sp_entity_id
      root["validUntil"] = valid_until.utc.strftime('%Y-%m-%dT%H:%M:%SZ') if valid_until
      root["cacheDuration"] = "PT#{cache_duration}S" if cache_duration

      namespaces.each { |k, v| root.add_namespace(k, v) }
      meta_doc.root = root

      root
    end

    def add_sp_sso_element(root, settings)
      sp_sso = Nokogiri::XML::Node.new("md:SPSSODescriptor", root)
      sp_sso["protocolSupportEnumeration"] = "urn:oasis:names:tc:SAML:2.0:protocol"
      sp_sso["AuthnRequestsSigned"] = settings.security[:authn_requests_signed].to_s
      sp_sso["WantAssertionsSigned"] = settings.security[:want_assertions_signed].to_s
      root.add_child(sp_sso)
      sp_sso
    end

    # Add KeyDescriptor elements for SP certificates.
    def add_sp_certificates(sp_sso, settings)
      certs = settings.get_sp_certs

      certs[:signing].each { |cert, _| add_sp_cert_element(sp_sso, cert, :signing) }

      if settings.security[:want_assertions_encrypted]
        certs[:encryption].each { |cert, _| add_sp_cert_element(sp_sso, cert, :encryption) }
      end

      sp_sso
    end

    def add_sp_service_elements(sp_sso, settings)
      if settings.single_logout_service_url
        logout_service = Nokogiri::XML::Node.new("md:SingleLogoutService", sp_sso)
        logout_service["Binding"] = settings.single_logout_service_binding
        logout_service["Location"] = settings.single_logout_service_url
        logout_service["ResponseLocation"] = settings.single_logout_service_url
        sp_sso.add_child(logout_service)
      end

      if settings.name_identifier_format
        nameid = Nokogiri::XML::Node.new("md:NameIDFormat", sp_sso)
        nameid.content = settings.name_identifier_format
        sp_sso.add_child(nameid)
      end

      if settings.assertion_consumer_service_url
        acs = Nokogiri::XML::Node.new("md:AssertionConsumerService", sp_sso)
        acs["Binding"] = settings.assertion_consumer_service_binding
        acs["Location"] = settings.assertion_consumer_service_url
        acs["isDefault"] = "true"
        acs["index"] = "0"
        sp_sso.add_child(acs)
      end

      if settings.attribute_consuming_service.configured?
        sp_acs = Nokogiri::XML::Node.new("md:AttributeConsumingService", sp_sso)
        sp_acs["isDefault"] = "true"
        sp_acs["index"] = settings.attribute_consuming_service.index.to_s
        sp_sso.add_child(sp_acs)

        srv_name = Nokogiri::XML::Node.new("md:ServiceName", sp_acs)
        srv_name["xml:lang"] = "en"
        srv_name.content = settings.attribute_consuming_service.name
        sp_acs.add_child(srv_name)

        settings.attribute_consuming_service.attributes.each do |attribute|
          sp_req_attr = Nokogiri::XML::Node.new("md:RequestedAttribute", sp_acs)
          sp_req_attr["NameFormat"] = attribute[:name_format]
          sp_req_attr["Name"] = attribute[:name]
          sp_req_attr["FriendlyName"] = attribute[:friendly_name]
          sp_req_attr["isRequired"] = attribute[:is_required].to_s
          sp_acs.add_child(sp_req_attr)

          next if attribute[:attribute_value].nil?

          Array(attribute[:attribute_value]).each do |value|
            sp_attr_val = Nokogiri::XML::Node.new("saml:AttributeValue", sp_req_attr)
            sp_attr_val.content = value.to_s
            sp_req_attr.add_child(sp_attr_val)
          end
        end
      end

      sp_sso
    end

    # can be overridden in subclass
    def add_extras(root, _settings)
      root
    end

    def embed_signature(meta_doc, settings)
      return unless settings.security[:metadata_signed]

      cert, private_key = settings.get_sp_signing_pair
      return unless private_key && cert

      meta_doc.sign_document(private_key, cert, settings.get_sp_signature_method, settings.get_sp_digest_method)
    end

    def output_xml(meta_doc, pretty_print)
      if pretty_print
        meta_doc.to_xml(indent: 2)
      else
        meta_doc.to_xml
      end
    end

    private

    def add_sp_cert_element(sp_sso, cert, use)
      return unless cert

      cert_text = Base64.encode64(cert.to_der).delete("\n")
      kd = Nokogiri::XML::Node.new("md:KeyDescriptor", sp_sso)
      kd["use"] = use.to_s
      sp_sso.add_child(kd)

      ki = Nokogiri::XML::Node.new("ds:KeyInfo", kd)
      ki.add_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
      kd.add_child(ki)

      xd = Nokogiri::XML::Node.new("ds:X509Data", ki)
      ki.add_child(xd)

      xc = Nokogiri::XML::Node.new("ds:X509Certificate", xd)
      xc.content = cert_text
      xd.add_child(xc)
    end
  end
end

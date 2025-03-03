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
      meta_doc = RubySaml::XML::Document.new
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
      meta_doc.encoding = 'UTF-8'
    end

    def add_root_element(meta_doc, settings, valid_until, cache_duration)
      root = Nokogiri::XML::Element.new("md:EntityDescriptor", meta_doc)
      root["xmlns:md"] = "urn:oasis:names:tc:SAML:2.0:metadata"

      if settings.attribute_consuming_service.configured?
        root["xmlns:saml"] = "urn:oasis:names:tc:SAML:2.0:assertion"
      end

      root["ID"] = RubySaml::Utils.uuid
      root["entityID"] = settings.sp_entity_id if settings.sp_entity_id
      root["validUntil"] = valid_until.utc.strftime('%Y-%m-%dT%H:%M:%SZ') if valid_until
      root["cacheDuration"] = "PT#{cache_duration}S" if cache_duration

      meta_doc.add_child(root)
      root
    end

    def add_sp_sso_element(root, settings)
      sp_sso = Nokogiri::XML::Element.new("md:SPSSODescriptor", root.document)
      sp_sso["protocolSupportEnumeration"] = "urn:oasis:names:tc:SAML:2.0:protocol"
      sp_sso["AuthnRequestsSigned"] = settings.security[:authn_requests_signed] ? "true" : "false"
      sp_sso["WantAssertionsSigned"] = settings.security[:want_assertions_signed] ? "true" : "false"

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
        slo = Nokogiri::XML::Element.new("md:SingleLogoutService", sp_sso.document)
        slo["Binding"] = settings.single_logout_service_binding
        slo["Location"] = settings.single_logout_service_url
        slo["ResponseLocation"] = settings.single_logout_service_url
        sp_sso.add_child(slo)
      end

      if settings.name_identifier_format
        nameid = Nokogiri::XML::Element.new("md:NameIDFormat", sp_sso.document)
        nameid.content = settings.name_identifier_format
        sp_sso.add_child(nameid)
      end

      if settings.assertion_consumer_service_url
        acs = Nokogiri::XML::Element.new("md:AssertionConsumerService", sp_sso.document)
        acs["Binding"] = settings.assertion_consumer_service_binding
        acs["Location"] = settings.assertion_consumer_service_url
        acs["isDefault"] = "true"
        acs["index"] = "0"
        sp_sso.add_child(acs)
      end

      if settings.attribute_consuming_service.configured?
        sp_acs = Nokogiri::XML::Element.new("md:AttributeConsumingService", sp_sso.document)
        sp_acs["isDefault"] = "true"
        sp_acs["index"] = settings.attribute_consuming_service.index

        srv_name = Nokogiri::XML::Element.new("md:ServiceName", sp_sso.document)
        srv_name["xml:lang"] = "en"
        srv_name.content = settings.attribute_consuming_service.name
        sp_acs.add_child(srv_name)

        settings.attribute_consuming_service.attributes.each do |attribute|
          sp_req_attr = Nokogiri::XML::Element.new("md:RequestedAttribute", sp_sso.document)
          sp_req_attr["NameFormat"] = attribute[:name_format]
          sp_req_attr["Name"] = attribute[:name]
          sp_req_attr["FriendlyName"] = attribute[:friendly_name]
          sp_req_attr["isRequired"] = attribute[:is_required] ? "true" : "false"

          next if attribute[:attribute_value].nil?

          Array(attribute[:attribute_value]).each do |value|
            sp_attr_val = Nokogiri::XML::Element.new("saml:AttributeValue", sp_sso.document)
            sp_attr_val.content = value.to_s
            sp_req_attr.add_child(sp_attr_val)
          end

          sp_acs.add_child(sp_req_attr)
        end

        sp_sso.add_child(sp_acs)
      end

      # With OpenSSO, it might be required to also include
      #  <md:RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:query="urn:oasis:names:tc:SAML:metadata:ext:query" xsi:type="query:AttributeQueryDescriptorType" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
      #  <md:XACMLAuthzDecisionQueryDescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>

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
      ret = +''

      # pretty print the XML so IdP administrators can easily see what the SP supports
      if pretty_print
        ret = meta_doc.to_xml(indent: 1)
      else
        ret = meta_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
      end

      ret
    end

    private

    def add_sp_cert_element(sp_sso, cert, use)
      return unless cert
      cert_text = Base64.encode64(cert.to_der).gsub("\n", '')

      kd = Nokogiri::XML::Element.new("md:KeyDescriptor", sp_sso.document)
      kd["use"] = use.to_s

      ki = Nokogiri::XML::Element.new("ds:KeyInfo", sp_sso.document)
      ki["xmlns:ds"] = "http://www.w3.org/2000/09/xmldsig#"

      xd = Nokogiri::XML::Element.new("ds:X509Data", sp_sso.document)

      xc = Nokogiri::XML::Element.new("ds:X509Certificate", sp_sso.document)
      xc.content = cert_text

      xd.add_child(xc)
      ki.add_child(xd)
      kd.add_child(ki)
      sp_sso.add_child(kd)
    end
  end
end
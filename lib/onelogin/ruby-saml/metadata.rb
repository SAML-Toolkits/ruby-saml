require "uri"
require "uuid"

require "onelogin/ruby-saml/logging"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Metadata. XML Metadata Builder
    # 
    class Metadata

      # Return SP metadata based on the settings.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param pretty_print [Boolean] Pretty print or not the response 
      #                               (No pretty print if you gonna validate the signature)
      # @return [String] XML Metadata of the Service Provider
      #
      def generate(settings, pretty_print=false)
        meta_doc = XMLSecurity::Document.new
        namespaces = {
            "xmlns:md" => "urn:oasis:names:tc:SAML:2.0:metadata"
        }
        if settings.attribute_consuming_service.configured?
          namespaces["xmlns:saml"] = "urn:oasis:names:tc:SAML:2.0:assertion"
        end
        root = meta_doc.add_element "md:EntityDescriptor", namespaces
        sp_sso = root.add_element "md:SPSSODescriptor", {
            "protocolSupportEnumeration" => "urn:oasis:names:tc:SAML:2.0:protocol",
            "AuthnRequestsSigned" => settings.security[:authn_requests_signed],
            "WantAssertionsSigned" => settings.security[:want_assertions_signed],
        }

        cert = settings.get_sp_cert
        if cert
          intermediate_certs = settings.get_sp_intermediate_certs

          add_sp_cert(sp_sso, "signing", cert, intermediate_certs)
          add_sp_cert(sp_sso, "encryption", cert, intermediate_certs)
        end

        root.attributes["ID"] = "_" + UUID.new.generate
        if settings.issuer
          root.attributes["entityID"] = settings.issuer
        end
        if settings.single_logout_service_url
          sp_sso.add_element "md:SingleLogoutService", {
              "Binding" => settings.single_logout_service_binding,
              "Location" => settings.single_logout_service_url,
              "ResponseLocation" => settings.single_logout_service_url
          }
        end
        if settings.name_identifier_format
          nameid = sp_sso.add_element "md:NameIDFormat"
          nameid.text = settings.name_identifier_format
        end
        if settings.assertion_consumer_service_url
          sp_sso.add_element "md:AssertionConsumerService", {
              "Binding" => settings.assertion_consumer_service_binding,
              "Location" => settings.assertion_consumer_service_url,
              "isDefault" => true,
              "index" => 0
          }
        end

        if settings.attribute_consuming_service.configured?
          sp_acs = sp_sso.add_element "md:AttributeConsumingService", {
            "isDefault" => "true",
            "index" => settings.attribute_consuming_service.index 
          }
          srv_name = sp_acs.add_element "md:ServiceName", {
            "xml:lang" => "en"
          }
          srv_name.text = settings.attribute_consuming_service.name
          settings.attribute_consuming_service.attributes.each do |attribute|
            sp_req_attr = sp_acs.add_element "md:RequestedAttribute", {
              "NameFormat" => attribute[:name_format],
              "Name" => attribute[:name], 
              "FriendlyName" => attribute[:friendly_name]
            }
            unless attribute[:attribute_value].nil?
              sp_attr_val = sp_req_attr.add_element "saml:AttributeValue"
              sp_attr_val.text = attribute[:attribute_value]
            end
          end
        end

        # With OpenSSO, it might be required to also include
        #  <md:RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:query="urn:oasis:names:tc:SAML:metadata:ext:query" xsi:type="query:AttributeQueryDescriptorType" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
        #  <md:XACMLAuthzDecisionQueryDescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>

        meta_doc << REXML::XMLDecl.new("1.0", "UTF-8")

        # embed signature
        if settings.security[:metadata_signed] && settings.private_key && settings.certificate
          private_key = settings.get_sp_key
          meta_doc.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        ret = ""
        # pretty print the XML so IdP administrators can easily see what the SP supports
        if pretty_print
          meta_doc.write(ret, 1)
        else 
          ret = meta_doc.to_s
        end

        return ret
      end

      private

      def add_sp_cert(sp_sso_descriptor, use, sp_cert, intermediate_certs)
        # Add KeyDescriptor if messages will be signed / encrypted:
        key_descriptor = sp_sso_descriptor.add_element "md:KeyDescriptor", { "use" => use }
        key_info = key_descriptor.add_element "ds:KeyInfo", { "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#" }
        x509_data = key_info.add_element "ds:X509Data"

        x509_certificate = x509_data.add_element "ds:X509Certificate"
        x509_certificate.text = get_cert_text(sp_cert)

        # Include intermediate certificates if any exist:
        if intermediate_certs
          intermediate_certs.each do |intermediate_cert|
            x509_intermediate_cert = x509_data.add_element "ds:X509Certificate"
            x509_intermediate_cert.text = get_cert_text(intermediate_cert)
          end
        end
      end

      def get_cert_text(cert)
        Base64.encode64(cert.to_der).gsub("\n", '')
      end
    end
  end
end

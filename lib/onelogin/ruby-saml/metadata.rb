require "uri"
require "uuid"

require "onelogin/ruby-saml/logging"

# Class to return SP metadata based on the settings requested.
# Return this XML in a controller, then give that URL to the the
# IdP administrator.  The IdP will poll the URL and your settings
# will be updated automatically
module OneLogin
  module RubySaml
    class Metadata
      def generate(settings, pretty_print=true)
        meta_doc = XMLSecurity::Document.new
        root = meta_doc.add_element "md:EntityDescriptor", {
            "xmlns:md" => "urn:oasis:names:tc:SAML:2.0:metadata"
        }
        sp_sso = root.add_element "md:SPSSODescriptor", {
            "protocolSupportEnumeration" => "urn:oasis:names:tc:SAML:2.0:protocol",
            "AuthnRequestsSigned" => settings.security[:authn_requests_signed],
            # However we would like assertions signed if idp_cert_fingerprint or idp_cert is set
            "WantAssertionsSigned" => !!(settings.idp_cert_fingerprint || settings.idp_cert)
        }
        root.attributes["ID"] = "_" + UUID.new.generate
        if settings.issuer
          root.attributes["entityID"] = settings.issuer
        end
        if settings.single_logout_service_url
          sp_sso.add_element "md:SingleLogoutService", {
              "Binding" => settings.single_logout_service_binding,
              "Location" => settings.single_logout_service_url,
              "ResponseLocation" => settings.single_logout_service_url,
              "isDefault" => true,
              "index" => 0
          }
        end
        if settings.name_identifier_format
          name_id = sp_sso.add_element "md:NameIDFormat"
          name_id.text = settings.name_identifier_format
        end
        if settings.assertion_consumer_service_url
          sp_sso.add_element "md:AssertionConsumerService", {
              "Binding" => settings.assertion_consumer_service_binding,
              "Location" => settings.assertion_consumer_service_url,
              "isDefault" => true,
              "index" => 0
          }
        end

        # Add KeyDescriptor if messages will be signed
        cert = settings.get_sp_cert()
        if cert
          kd = sp_sso.add_element "md:KeyDescriptor", { "use" => "signing" }
          ki = kd.add_element "ds:KeyInfo", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"}
          xd = ki.add_element "ds:X509Data"
          xc = xd.add_element "ds:X509Certificate"
          xc.text = Base64.encode64(cert.to_der).gsub("\n", '')
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
              sp_attr_val = sp_req_attr.add_element "md:AttributeValue"
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
          private_key = settings.get_sp_key()
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
    end
  end
end

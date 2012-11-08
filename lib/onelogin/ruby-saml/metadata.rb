require "rexml/document"
require "rexml/xpath"
require "uri"

# Class to return SP metadata based on the settings requested.
# Return this XML in a controller, then give that URL to the the 
# IdP administrator.  The IdP will poll the URL and your settings
# will be updated automatically
module Onelogin
  module Saml
    include REXML
    class Metadata
      def generate(settings)
        meta_doc = REXML::Document.new
        root = meta_doc.add_element "md:EntityDescriptor", {
            "xmlns:md" => "urn:oasis:names:tc:SAML:2.0:metadata"
        }
        sp_sso = root.add_element "md:SPSSODescriptor", {
            "protocolSupportEnumeration" => "urn:oasis:names:tc:SAML:2.0:protocol",
            # Metadata request need not be signed (as we don't publish our cert)
            "AuthnRequestsSigned" => false,
            # However we would like assertions signed if idp_cert_fingerprint or idp_cert is set
            "WantAssertionsSigned" => (!settings.idp_cert_fingerprint.nil? || !settings.idp_cert.nil?)
        }
        if settings.issuer != nil
          root.attributes["entityID"] = settings.issuer
        end
        if settings.assertion_consumer_logout_service_url != nil
          sp_sso.add_element "md:SingleLogoutService", {
              # Add this as a setting to create different bindings?
              "Binding" => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
              "Location" => settings.assertion_consumer_logout_service_url,
              "ResponseLocation" => settings.assertion_consumer_logout_service_url,
              "isDefault" => true,
              "index" => 0
          }
        end
        if settings.name_identifier_format != nil
          name_id = sp_sso.add_element "md:NameIDFormat"
          name_id.text = settings.name_identifier_format
        end
        if settings.assertion_consumer_service_url != nil
          sp_sso.add_element "md:AssertionConsumerService", {
              # Add this as a setting to create different bindings?
              "Binding" => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
              "Location" => settings.assertion_consumer_service_url,
              "isDefault" => true,
              "index" => 0
          }
        end
        # With OpenSSO, it might be required to also include
        #  <md:RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:query="urn:oasis:names:tc:SAML:metadata:ext:query" xsi:type="query:AttributeQueryDescriptorType" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
        #  <md:XACMLAuthzDecisionQueryDescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>

        meta_doc << REXML::XMLDecl.new
        ret = ""
        # pretty print the XML so IdP administrators can easily see what the SP supports
        meta_doc.write(ret, 1)

        Logging.debug "Generated metadata:\n#{ret}"

        ret
      end
    end
  end
end

require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"

module Onelogin
  module Saml
  include REXML
    class Authrequest
      def create(settings, params = {})
        params = {} if params.nil?

        request_doc = create_authentication_xml_doc(settings)

        request = ""
        request_doc.write(request)

        Logging.debug "Created AuthnRequest: #{request}"

        request           = Zlib::Deflate.deflate(request, 9)[2..-5] if settings.compress_request
        base64_request    = Base64.encode64(request)
        encoded_request   = CGI.escape(base64_request)
        params_prefix     = (settings.idp_sso_target_url =~ /\?/) ? '&' : '?'
        request_params    = "#{params_prefix}SAMLRequest=#{encoded_request}"

        params.each_pair do |key, value|
          request_params << "&#{key.to_s}=#{CGI.escape(value.to_s)}"
        end

        settings.idp_sso_target_url + request_params
      end

      def create_authentication_xml_doc(settings)
        uuid = "_" + UUID.new.generate
        time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Create AuthnRequest root element using REXML 
        request_doc = REXML::Document.new

        root = request_doc.add_element "samlp:AuthnRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = "2.0"
        root.attributes['Destination'] = settings.idp_sso_target_url unless settings.idp_sso_target_url.nil?

        # Conditionally defined elements based on settings
        if settings.assertion_consumer_service_url != nil
          root.attributes["AssertionConsumerServiceURL"] = settings.assertion_consumer_service_url
        end
        if settings.issuer != nil
          issuer = root.add_element "saml:Issuer", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
          issuer.text = settings.issuer
        end
        if settings.name_identifier_format != nil
          root.add_element "samlp:NameIDPolicy", { 
              "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
              # Might want to make AllowCreate a setting?
              "AllowCreate" => "true",
              "Format" => settings.name_identifier_format
          }
        end

        # BUG fix here -- if an authn_context is defined, add the tags with an "exact"
        # match required for authentication to succeed.  If this is not defined, 
        # the IdP will choose default rules for authentication.  (Shibboleth IdP)
        if settings.authn_context != nil
          requested_context = root.add_element "samlp:RequestedAuthnContext", { 
            "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
            "Comparison" => "exact",
          }
          class_ref = requested_context.add_element "saml:AuthnContextClassRef", { 
            "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
          }
          class_ref.text = settings.authn_context
        end
        request_doc
      end

    end
  end
end

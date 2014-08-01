require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"

module OneLogin
  module RubySaml
  include REXML
    class Authrequest
      def create(settings, params = {})
        params = {} if params.nil?

        request_doc = create_authentication_xml_doc(settings)
        request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        # Add XML-Signature node and sign the document if requested in settings
        request = ""
        if settings.private_key
          request_doc.root.attributes["xmlns:ds"] = "http://www.w3.org/2000/09/xmldsig#"
          request_doc.root.attributes["xmlns:ec"] = "http://www.w3.org/2001/10/xml-exc-c14n#"
          signature = request_doc.root.add_element "Signature", {
            "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
          }
          signed_info = signature.add_element "SignedInfo"
          signed_info.add_element "CanonicalizationMethod", {
            "Algorithm" => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
          }
          signed_info.add_element "SignatureMethod", {
            "Algorithm" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
          }
          reference = signed_info.add_element "Reference", {
            "URI" => ""
          }
          transforms = reference.add_element "Transforms"
          transforms.add_element "Transform", {
            "Algorithm" => "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
          }
          transform = transforms.add_element "Transform", {
            "Algorithm" => "http://www.w3.org/2001/10/xml-exc-c14n#"
          }
          reference.add_element "DigestMethod", {
            "Algorithm" => "http://www.w3.org/2000/09/xmldsig#sha1"
          }
          reference.add_element "DigestValue"
          signature.add_element "SignatureValue"
          key_info = signature.add_element "KeyInfo"
          x509_data = key_info.add_element "X509Data"
          x509_certificate = x509_data.add_element "X509Certificate"
          certificate = OpenSSL::X509::Certificate.new(File.read(settings.certificate))
          # Remove newlines and BEGIN & END CERTIFICATE lines
          x509_certificate.text = certificate.to_pem.lines.map(&:chomp)[1..-2].join("")
          unsigned_xml = ""
          request_doc.write(unsigned_xml)
          private_key = OpenSSL::PKey::RSA.new(File.read(settings.private_key), settings.private_key_pass)
          unsigned_document = Xmldsig::SignedDocument.new(unsigned_xml)
          signed_xml = unsigned_document.sign(private_key)
          signed_document = Xmldsig::SignedDocument.new(signed_xml)
          # Remove all newlines, strip and join the signed XML
          request = signed_document.document.to_s.lines.map(&:chomp).map(&:strip).join("")
        else
          request_doc.write(request)
        end
        # End XML-Signature

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
        root.attributes['IsPassive'] = settings.passive unless settings.passive.nil?
        root.attributes['ProtocolBinding'] = settings.protocol_binding unless settings.protocol_binding.nil?
        root.attributes["AttributeConsumingServiceIndex"] = settings.attributes_index unless settings.attributes_index.nil?

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

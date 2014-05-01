require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"

module OneLogin
  module RubySaml
    include REXML

    class IdpMetadataParser

      METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
      DSIG     = "http://www.w3.org/2000/09/xmldsig#"

      attr_reader :document

      def parse(idp_metadata)
        @document = REXML::Document.new(idp_metadata)

        OneLogin::RubySaml::Settings.new.tap do |settings|
          settings.entity_id = entity_id
          settings.idp_sso_target_url = single_signon_service_url
          settings.idp_slo_target_url = single_logout_service_url
          settings.idp_cert = certificate
          settings.idp_cert_fingerprint = fingerprint
          settings.protocol_binding = single_signon_service_binding
        end
      end

      private

      def entity_id
        document.root.attributes["entityID"]
      end

      def single_signon_service_binding
        node = REXML::XPath.first(document, "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService/@Binding", { "md" => METADATA })
        node.value if node
      end

      def single_signon_service_url
        node = REXML::XPath.first(document, "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService/@Location", { "md" => METADATA })
        node.value if node
      end

      def single_logout_service_url
        node = REXML::XPath.first(document, "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService/@Location", { "md" => METADATA })
        node.value if node
      end

      def certificate
        @certificate ||= begin
          node = REXML::XPath.first(document, "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate", { "md" => METADATA, "ds" => DSIG })
          OpenSSL::X509::Certificate.new(Base64.decode64(node.text)) if node
        end
      end

      def fingerprint
        @fingerprint ||= begin
          if certificate
            Digest::SHA1.hexdigest(certificate.to_der).upcase.scan(/../).join(":")
          end
        end
      end
    end
  end
end

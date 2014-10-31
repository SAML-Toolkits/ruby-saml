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

      def parse_remote(url, validate_cert = true)
        idp_metadata = get_idp_metadata(url, validate_cert)
        parse(idp_metadata)
      end

      def parse(idp_metadata)
        @document = REXML::Document.new(idp_metadata)

        OneLogin::RubySaml::Settings.new.tap do |settings|

          settings.idp_sso_target_url = single_signon_service_url
          settings.idp_slo_target_url = single_logout_service_url
          settings.idp_cert_fingerprint = fingerprint
        end
      end

      private

      # Retrieve the remote IdP metadata from the URL or a cached copy
      # # returns a REXML document of the metadata
      def get_idp_metadata(url, validate_cert)
        uri = URI.parse(url)
        if uri.scheme == "http"
          response = Net::HTTP.get_response(uri)
          meta_text = response.body
        elsif uri.scheme == "https"
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          # Most IdPs will probably use self signed certs
          if validate_cert
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          else
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          end
          get = Net::HTTP::Get.new(uri.request_uri)
          response = http.request(get)
          meta_text = response.body
        end
        meta_text
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
          Base64.decode64(node.text) if node
        end
      end

      def fingerprint
        @fingerprint ||= begin
          if certificate
            cert = OpenSSL::X509::Certificate.new(certificate)
            Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
          end
        end
      end
    end
  end
end

require "base64"
require "uuid"
require "zlib"
require "cgi"
require "net/http"
require "net/https"
require "rexml/document"
require "rexml/xpath"

# Only supports SAML 2.0
module OneLogin
  module RubySaml
    include REXML

    # Auxiliary class to retrieve and parse the Identity Provider Metadata
    #
    class IdpMetadataParser

      METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
      DSIG     = "http://www.w3.org/2000/09/xmldsig#"

      attr_reader :document
      attr_reader :response

      # Parse the Identity Provider metadata and update the settings with the
      # IdP values
      #
      # @param (see IdpMetadataParser#get_idp_metadata)
      # @return (see IdpMetadataParser#get_idp_metadata)
      # @raise (see IdpMetadataParser#get_idp_metadata)
      def parse_remote(url, validate_cert = true)
        idp_metadata = get_idp_metadata(url, validate_cert)
        parse(idp_metadata)
      end

      # Parse the Identity Provider metadata and update the settings with the IdP values
      # @param idp_metadata [String] 
      #
      def parse(idp_metadata)
        @document = REXML::Document.new(idp_metadata)

        OneLogin::RubySaml::Settings.new.tap do |settings|
          settings.idp_entity_id = idp_entity_id
          settings.name_identifier_format = idp_name_id_format
          settings.idp_sso_target_url = single_signon_service_url
          settings.idp_slo_target_url = single_logout_service_url
          settings.idp_cert_fingerprint = fingerprint
        end
      end

      private

      # Retrieve the remote IdP metadata from the URL or a cached copy.
      # @param url [String] Url where the XML of the Identity Provider Metadata is published.
      # @param validate_cert [Boolean] If true and the URL is HTTPs, the cert of the domain is checked.
      # @return [REXML::document] Parsed XML IdP metadata
      # @raise [HttpError] Failure to fetch remote IdP metadata
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

            # Net::HTTP in Ruby 1.8 did not set the default certificate store
            # automatically when VERIFY_PEER was specified.
            if RUBY_VERSION < '1.9' && !http.ca_file && !http.ca_path && !http.cert_store
              http.cert_store = OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE
            end
          else
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          end
          get = Net::HTTP::Get.new(uri.request_uri)
          response = http.request(get)
          meta_text = response.body
        else
          raise ArgumentError.new("url must begin with http or https")
        end

        unless response.is_a? Net::HTTPSuccess
          raise OneLogin::RubySaml::HttpError.new("Failed to fetch idp metadata")
        end

        meta_text
      end

      # @return [String|nil] IdP Entity ID value if exists
      #
      def idp_entity_id
        node = REXML::XPath.first(
          document,
          "/md:EntityDescriptor/@entityID",
          { "md" => METADATA }
        )
        node.value if node
      end

      # @return [String|nil] IdP Name ID Format value if exists
      #
      def idp_name_id_format
        node = REXML::XPath.first(
          document,
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat",
          { "md" => METADATA }
        )
        node.text if node
      end

      # @return [String|nil] SingleSignOnService endpoint if exists
      #
      def single_signon_service_url
        node = REXML::XPath.first(
          document,
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService/@Location",
          { "md" => METADATA }
        )
        node.value if node
      end

      # @return [String|nil] SingleLogoutService endpoint if exists
      #
      def single_logout_service_url
        node = REXML::XPath.first(
          document,
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService/@Location",
          { "md" => METADATA }
        )
        node.value if node
      end

      # @return [String|nil] X509Certificate if exists
      #
      def certificate
        @certificate ||= begin
          node = REXML::XPath.first(
            document,
            "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
            { "md" => METADATA, "ds" => DSIG }
          )
          Base64.decode64(node.text) if node
        end
      end

      # @return [String|nil] the SHA-1 fingerpint of the X509Certificate if it exists
      #
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

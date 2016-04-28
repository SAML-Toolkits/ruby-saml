require "base64"
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

      METADATA       = "urn:oasis:names:tc:SAML:2.0:metadata"
      DSIG           = "http://www.w3.org/2000/09/xmldsig#"
      NAME_FORMAT    = "urn:oasis:names:tc:SAML:2.0:attrname-format:*"
      SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"

      attr_reader :document
      attr_reader :response

      # Parse the Identity Provider metadata and update the settings with the
      # IdP values
      #
      # @param (see IdpMetadataParser#get_idp_metadata)
      # @param options  [Hash]   :settings to provide the OneLogin::RubySaml::Settings object
      # @return (see IdpMetadataParser#get_idp_metadata)
      # @raise (see IdpMetadataParser#get_idp_metadata)
      def parse_remote(url, validate_cert = true, options = {})
        idp_metadata = get_idp_metadata(url, validate_cert)
        parse(idp_metadata, options)
      end

      # Parse the Identity Provider metadata and update the settings with the IdP values
      # @param idp_metadata [String] 
      # @param options  [Hash]   :settings to provide the OneLogin::RubySaml::Settings object
      #
      def parse(idp_metadata, options = {})
        @document = REXML::Document.new(idp_metadata)

        (options[:settings] || OneLogin::RubySaml::Settings.new).tap do |settings|
          settings.idp_entity_id = idp_entity_id
          settings.name_identifier_format = idp_name_id_format
          settings.idp_sso_target_url = single_signon_service_url(options)
          settings.idp_slo_target_url = single_logout_service_url(options)
          settings.idp_cert = certificate_base64
          settings.idp_cert_fingerprint = fingerprint(settings.idp_cert_fingerprint_algorithm)
          settings.idp_attribute_names = attribute_names
          settings.idp_cert_fingerprint = fingerprint(settings.idp_cert_fingerprint_algorithm)
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

      # @param binding_priority [Array]
      # @return [String|nil] SingleSignOnService binding if exists
      #
      def single_signon_service_binding(binding_priority = nil)
        nodes = REXML::XPath.match(
          document,
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService/@Binding",
          { "md" => METADATA }
        )
        if binding_priority
          values = nodes.map(&:value)
          binding_priority.detect{ |binding| values.include? binding }
        else
          nodes.first.value if nodes.any?
        end
      end

      # @param options [Hash]
      # @return [String|nil] SingleSignOnService endpoint if exists
      #
      def single_signon_service_url(options = {})
        binding = options[:sso_binding] || "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        node = REXML::XPath.first(
          document,
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding=\"#{binding}\"]/@Location",
          { "md" => METADATA }
        )
        node.value if node
      end

      # @param binding_priority [Array]
      # @return [String|nil] SingleLogoutService binding if exists
      #
      def single_logout_service_binding(binding_priority = nil)
        nodes = REXML::XPath.match(
          document,
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService/@Binding",
          { "md" => METADATA }
        )
        if binding_priority
          values = nodes.map(&:value)
          binding_priority.detect{ |binding| values.include? binding }
        else
          nodes.first.value if nodes.any?
        end
      end

      # @param options [Hash]
      # @return [String|nil] SingleLogoutService endpoint if exists
      #
      def single_logout_service_url(options = {})
        binding = options[:slo_binding] || "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        node = REXML::XPath.first(
          document,
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding=\"#{binding}\"]/@Location",
          { "md" => METADATA }
        )
        node.value if node
      end

      # @return [String|nil] Unformatted Certificate if exists
      #
      def certificate_base64
        @certificate_base64 ||= begin
          node = REXML::XPath.first(
              document,
              "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
              { "md" => METADATA, "ds" => DSIG }
          )

          unless node
            node = REXML::XPath.first(
                document,
                "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
                { "md" => METADATA, "ds" => DSIG }
            )
          end
          node.text if node
        end
      end

      # @return [String|nil] X509Certificate if exists
      #
      def certificate
        @certificate ||= begin
          Base64.decode64(certificate_base64) if certificate_base64
        end
      end


      # @return [String|nil] the SHA-1 fingerpint of the X509Certificate if it exists
      #
      def fingerprint(fingerprint_algorithm)
        @fingerprint ||= begin
          if certificate
            cert = OpenSSL::X509::Certificate.new(certificate)

            fingerprint_alg = XMLSecurity::BaseDocument.new.algorithm(fingerprint_algorithm).new
            fingerprint_alg.hexdigest(cert.to_der).upcase.scan(/../).join(":")
          end
        end
      end

      # @return [Array] the names of all SAML attributes if any exist
      #
      def attribute_names
        nodes = REXML::XPath.match(
          document,
          "/md:EntityDescriptor/md:IDPSSODescriptor/saml:Attribute/@Name",
          { "md" => METADATA, "NameFormat" => NAME_FORMAT, "saml" => SAML_ASSERTION }
        )
        nodes.map(&:value)
      end
    end
  end
end

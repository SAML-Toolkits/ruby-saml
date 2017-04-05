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
      attr_reader :parse_options

      # Parse the Identity Provider metadata and update the settings with the
      # IdP values
      #
      # @param (see IdpMetadataParser#get_idp_metadata)
      # @param options  [Hash]   :settings to provide the OneLogin::RubySaml::Settings object or an hash for Settings overrides
      # @return (see IdpMetadataParser#get_idp_metadata)
      # @raise (see IdpMetadataParser#get_idp_metadata)
      def parse_remote(url, validate_cert = true, options = {})
        idp_metadata = get_idp_metadata(url, validate_cert)
        parse(idp_metadata, options)
      end

      # Parse the Identity Provider metadata and update the settings with the IdP values
      # @param idp_metadata [String]
      # @param options  [Hash]   :settings to provide the OneLogin::RubySaml::Settings object or an hash for Settings overrides
      #
      def parse(idp_metadata, parse_options = {})
        @document = REXML::Document.new(idp_metadata)
        @parse_options = parse_options
        @entity_descriptor = nil

        settings = parse_options[:settings]
        if settings.nil? || settings.is_a?(Hash)
          settings = OneLogin::RubySaml::Settings.new(settings || {})
        end

        settings.tap do |settings|
          settings.idp_entity_id = idp_entity_id
          settings.name_identifier_format = idp_name_id_format
          settings.idp_sso_target_url = single_signon_service_url
          settings.idp_slo_target_url = single_logout_service_url
          settings.idp_cert = certificate_base64
          settings.idp_cert_fingerprint = fingerprint(settings.idp_cert_fingerprint_algorithm)
          settings.idp_attribute_names = attribute_names
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
        raise ArgumentError.new("url must begin with http or https") unless /^https?/ =~ uri.scheme
        http = Net::HTTP.new(uri.host, uri.port)

        if uri.scheme == "https"
          http.use_ssl = true
          # Most IdPs will probably use self signed certs
          http.verify_mode = validate_cert ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

          # Net::HTTP in Ruby 1.8 did not set the default certificate store
          # automatically when VERIFY_PEER was specified.
          if RUBY_VERSION < '1.9' && !http.ca_file && !http.ca_path && !http.cert_store
            http.cert_store = OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE
          end
        end

        get = Net::HTTP::Get.new(uri.request_uri)
        response = http.request(get)
        return response.body if response.is_a? Net::HTTPSuccess

        raise OneLogin::RubySaml::HttpError.new(
          "Failed to fetch idp metadata: #{response.code}: #{response.message}"
        )
      end

      def entity_descriptor
        @entity_descriptor ||= REXML::XPath.first(
          document,
          entity_descriptor_path,
          namespace
        )
      end

      def entity_descriptor_path
        path = "//md:EntityDescriptor"
        entity_id = parse_options[:entity_id]
        return path unless entity_id
        path << "[@entityID=\"#{entity_id}\"]"
      end

      # @return [String|nil] IdP Entity ID value if exists
      #
      def idp_entity_id
        entity_descriptor.attributes["entityID"]
      end

      # @return [String|nil] IdP Name ID Format value if exists
      #
      def idp_name_id_format
        node = REXML::XPath.first(
          entity_descriptor,
          "md:IDPSSODescriptor/md:NameIDFormat",
          namespace
        )
        node.text if node
      end

      # @param binding_priority [Array]
      # @return [String|nil] SingleSignOnService binding if exists
      #
      def single_signon_service_binding(binding_priority = nil)
        nodes = REXML::XPath.match(
          entity_descriptor,
          "md:IDPSSODescriptor/md:SingleSignOnService/@Binding",
          namespace
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
      def single_signon_service_url
        binding = parse_options[:sso_binding] || "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        node = REXML::XPath.first(
          entity_descriptor,
          "md:IDPSSODescriptor/md:SingleSignOnService[@Binding=\"#{binding}\"]/@Location",
          namespace
        )
        node.value if node
      end

      # @param binding_priority [Array]
      # @return [String|nil] SingleLogoutService binding if exists
      #
      def single_logout_service_binding(binding_priority = nil)
        nodes = REXML::XPath.match(
          entity_descriptor,
          "md:IDPSSODescriptor/md:SingleLogoutService/@Binding",
          namespace
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
      def single_logout_service_url
        binding = parse_options[:slo_binding] || "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        node = REXML::XPath.first(
          entity_descriptor,
          "md:IDPSSODescriptor/md:SingleLogoutService[@Binding=\"#{binding}\"]/@Location",
          namespace
        )
        node.value if node
      end

      # @return [String|nil] Unformatted Certificate if exists
      #
      def certificate_base64
        @certificate_base64 ||= begin
          node = REXML::XPath.first(
            entity_descriptor,
            "md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
            namespace
          )

          unless node
            node = REXML::XPath.first(
              entity_descriptor,
              "md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
              namespace
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
      def fingerprint(fingerprint_algorithm = XMLSecurity::Document::SHA1)
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
          entity_descriptor,
          "md:IDPSSODescriptor/saml:Attribute/@Name",
          namespace
        )
        nodes.map(&:value)
      end

      def namespace
        {
          "md" => METADATA,
          "NameFormat" => NAME_FORMAT,
          "saml" => SAML_ASSERTION,
          "ds" => DSIG
        }
      end
    end
  end
end

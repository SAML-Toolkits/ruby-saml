require "base64"
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

      module SamlMetadata
        module Vocabulary
          METADATA       = "urn:oasis:names:tc:SAML:2.0:metadata"
          DSIG           = "http://www.w3.org/2000/09/xmldsig#"
          NAME_FORMAT    = "urn:oasis:names:tc:SAML:2.0:attrname-format:*"
          SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
        end

        NAMESPACE = {
          "md" => Vocabulary::METADATA,
          "NameFormat" => Vocabulary::NAME_FORMAT,
          "saml" => Vocabulary::SAML_ASSERTION,
          "ds" => Vocabulary::DSIG
        }
      end

      include SamlMetadata::Vocabulary
      attr_reader :document
      attr_reader :response
      attr_reader :options

      # Parse the Identity Provider metadata and update the settings with the
      # IdP values
      #
      # @param url [String] Url where the XML of the Identity Provider Metadata is published.
      # @param validate_cert [Boolean] If true and the URL is HTTPs, the cert of the domain is checked.
      #
      # @param options [Hash] options used for parsing the metadata and the returned Settings instance
      # @option options [OneLogin::RubySaml::Settings, Hash] :settings the OneLogin::RubySaml::Settings object which gets the parsed metadata merged into or an hash for Settings overrides.
      # @option options [Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When ommitted, the first entity descriptor is used.
      #
      # @return [OneLogin::RubySaml::Settings]
      #
      # @raise [HttpError] Failure to fetch remote IdP metadata
      def parse_remote(url, validate_cert = true, options = {})
        idp_metadata = get_idp_metadata(url, validate_cert)
        parse(idp_metadata, options)
      end

      # Parse the Identity Provider metadata and return the results as Hash
      #
      # @param url [String] Url where the XML of the Identity Provider Metadata is published.
      # @param validate_cert [Boolean] If true and the URL is HTTPs, the cert of the domain is checked.
      #
      # @param options [Hash] options used for parsing the metadata
      # @option options [Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When ommitted, the first entity descriptor is used.
      #
      # @return [Hash]
      #
      # @raise [HttpError] Failure to fetch remote IdP metadata
      def parse_remote_to_hash(url, validate_cert = true, options = {})
        parse_remote_to_array(url, validate_cert, options)[0]
      end

      # Parse all Identity Provider metadata and return the results as Array
      #
      # @param url [String] Url where the XML of the Identity Provider Metadata is published.
      # @param validate_cert [Boolean] If true and the URL is HTTPs, the cert of the domain is checked.
      #
      # @param options [Hash] options used for parsing the metadata
      # @option options [Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When ommitted, all found IdPs are returned.
      #
      # @return [Array<Hash>]
      #
      # @raise [HttpError] Failure to fetch remote IdP metadata
      def parse_remote_to_array(url, validate_cert = true, options = {})
        idp_metadata = get_idp_metadata(url, validate_cert)
        parse_to_array(idp_metadata, options)
      end

      # Parse the Identity Provider metadata and update the settings with the IdP values
      #
      # @param idp_metadata [String]
      #
      # @param options [Hash] :settings to provide the OneLogin::RubySaml::Settings object or an hash for Settings overrides
      # @option options [OneLogin::RubySaml::Settings, Hash] :settings the OneLogin::RubySaml::Settings object which gets the parsed metadata merged into or an hash for Settings overrides.
      # @option options [Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When ommitted, the first entity descriptor is used.
      #
      # @return [OneLogin::RubySaml::Settings]
      def parse(idp_metadata, options = {})
        parsed_metadata = parse_to_hash(idp_metadata, options)

        settings = options[:settings]

        if settings.nil?
          OneLogin::RubySaml::Settings.new(parsed_metadata)
        elsif settings.is_a?(Hash)
          OneLogin::RubySaml::Settings.new(settings.merge(parsed_metadata))
        else
          merge_parsed_metadata_into(settings, parsed_metadata)
        end
      end

      # Parse the Identity Provider metadata and return the results as Hash
      #
      # @param idp_metadata [String]
      #
      # @param options [Hash] options used for parsing the metadata and the returned Settings instance
      # @option options [Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When ommitted, the first entity descriptor is used.
      #
      # @return [Hash]
      def parse_to_hash(idp_metadata, options = {})
        parse_to_array(idp_metadata, options)[0]
      end

      # Parse all Identity Provider metadata and return the results as Array
      #
      # @param idp_metadata [String]
      #
      # @param options [Hash] options used for parsing the metadata and the returned Settings instance
      # @option options [Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When ommitted, all found IdPs are returned.
      #
      # @return [Array<Hash>]
      def parse_to_array(idp_metadata, options = {})
        @document = REXML::Document.new(idp_metadata)
        @options = options

        idpsso_descriptors = IdpMetadata::get_idps(@document, options[:entity_id])
        if !idpsso_descriptors.any?
          raise ArgumentError.new("idp_metadata must contain an IDPSSODescriptor element")
        end

        return idpsso_descriptors.map{|id| IdpMetadata.new(id, id.parent.attributes["entityID"]).to_hash(options)}
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
        @response = http.request(get)
        return response.body if response.is_a? Net::HTTPSuccess

        raise OneLogin::RubySaml::HttpError.new(
          "Failed to fetch idp metadata: #{response.code}: #{response.message}"
        )
      end

      class IdpMetadata
        def self.get_idps(metadata_document, only_entity_id=nil)
          path = "//md:EntityDescriptor#{only_entity_id && '[@entityID="' + only_entity_id + '"]'}/md:IDPSSODescriptor"
          REXML::XPath.match(
            metadata_document,
            path,
            SamlMetadata::NAMESPACE
          )
        end

        def initialize(idpsso_descriptor, entity_id)
          @idpsso_descriptor = idpsso_descriptor
          @entity_id = entity_id
        end

        def to_hash(options = {})
          {
            :idp_entity_id => @entity_id,
            :name_identifier_format => idp_name_id_format,
            :idp_sso_target_url => single_signon_service_url(options),
            :idp_slo_target_url => single_logout_service_url(options),
            :idp_attribute_names => attribute_names,
            :idp_cert => nil,
            :idp_cert_fingerprint => nil,
            :idp_cert_multi => nil,
            :valid_until => valid_until
          }.tap do |response_hash|
            merge_certificates_into(response_hash) unless certificates.nil?
          end
        end

        # @return [String|nil] IdP Name ID Format value if exists
        #
        def idp_name_id_format
          node = REXML::XPath.first(
            @idpsso_descriptor,
            "md:NameIDFormat",
            SamlMetadata::NAMESPACE
          )
          Utils.element_text(node)
        end

        # @return [String|nil] 'validUntil' attribute of metadata
        #
        def valid_until
          root = @idpsso_descriptor.root
          root.attributes['validUntil'] if root && root.attributes
        end

        # @param binding_priority [Array]
        # @return [String|nil] SingleSignOnService binding if exists
        #
        def single_signon_service_binding(binding_priority = nil)
          nodes = REXML::XPath.match(
            @idpsso_descriptor,
            "md:SingleSignOnService/@Binding",
            SamlMetadata::NAMESPACE
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
          binding = single_signon_service_binding(options[:sso_binding])
          return if binding.nil?

          node = REXML::XPath.first(
            @idpsso_descriptor,
            "md:SingleSignOnService[@Binding=\"#{binding}\"]/@Location",
            SamlMetadata::NAMESPACE
          )
          return node.value if node
        end

        # @param binding_priority [Array]
        # @return [String|nil] SingleLogoutService binding if exists
        #
        def single_logout_service_binding(binding_priority = nil)
          nodes = REXML::XPath.match(
            @idpsso_descriptor,
            "md:SingleLogoutService/@Binding",
            SamlMetadata::NAMESPACE
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
          binding = single_logout_service_binding(options[:slo_binding])
          return if binding.nil?

          node = REXML::XPath.first(
            @idpsso_descriptor,
            "md:SingleLogoutService[@Binding=\"#{binding}\"]/@Location",
            SamlMetadata::NAMESPACE
          )
          return node.value if node
        end

        # @return [String|nil] Unformatted Certificate if exists
        #
        def certificates
          @certificates ||= begin
            signing_nodes = REXML::XPath.match(
              @idpsso_descriptor,
              "md:KeyDescriptor[not(contains(@use, 'encryption'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
              SamlMetadata::NAMESPACE
            )

            encryption_nodes = REXML::XPath.match(
              @idpsso_descriptor,
              "md:KeyDescriptor[not(contains(@use, 'signing'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
              SamlMetadata::NAMESPACE
            )

            return nil if signing_nodes.empty? && encryption_nodes.empty?

            certs = {}
            unless signing_nodes.empty?
              certs['signing'] = []
              signing_nodes.each do |cert_node|
                certs['signing'] << Utils.element_text(cert_node)
              end
            end

            unless encryption_nodes.empty?
              certs['encryption'] = []
              encryption_nodes.each do |cert_node|
                certs['encryption'] << Utils.element_text(cert_node)
              end
            end
            certs
          end
        end

        # @return [String|nil] the fingerpint of the X509Certificate if it exists
        #
        def fingerprint(certificate, fingerprint_algorithm = XMLSecurity::Document::SHA1)
          @fingerprint ||= begin
            return unless certificate

            cert = OpenSSL::X509::Certificate.new(Base64.decode64(certificate))

            fingerprint_alg = XMLSecurity::BaseDocument.new.algorithm(fingerprint_algorithm).new
            fingerprint_alg.hexdigest(cert.to_der).upcase.scan(/../).join(":")
          end
        end

        # @return [Array] the names of all SAML attributes if any exist
        #
        def attribute_names
          nodes = REXML::XPath.match(
            @idpsso_descriptor  ,
            "saml:Attribute/@Name",
            SamlMetadata::NAMESPACE
          )
          nodes.map(&:value)
        end

        def merge_certificates_into(parsed_metadata)
          if (certificates.size == 1 &&
              (certificates_has_one('signing') || certificates_has_one('encryption'))) ||
              (certificates_has_one('signing') && certificates_has_one('encryption') &&
              certificates["signing"][0] == certificates["encryption"][0])

            if certificates.key?("signing")
              parsed_metadata[:idp_cert] = certificates["signing"][0]
              parsed_metadata[:idp_cert_fingerprint] = fingerprint(
                parsed_metadata[:idp_cert],
                parsed_metadata[:idp_cert_fingerprint_algorithm]
              )
            else
              parsed_metadata[:idp_cert] = certificates["encryption"][0]
              parsed_metadata[:idp_cert_fingerprint] = fingerprint(
                parsed_metadata[:idp_cert],
                parsed_metadata[:idp_cert_fingerprint_algorithm]
              )
            end
          else
            # symbolize keys of certificates and pass it on
            parsed_metadata[:idp_cert_multi] = Hash[certificates.map { |k, v| [k.to_sym, v] }]
          end
        end

        def certificates_has_one(key)
          certificates.key?(key) && certificates[key].size == 1
        end
      end

      def merge_parsed_metadata_into(settings, parsed_metadata)
        parsed_metadata.each do |key, value|
          settings.send("#{key}=".to_sym, value)
        end

        settings
      end

      if self.respond_to?(:private_constant)
        private_constant :SamlMetadata, :IdpMetadata
      end
    end
  end
end

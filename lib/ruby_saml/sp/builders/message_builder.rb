# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # Base class for SAML message builders
      #
      # Provides common functionality for building SAML requests and responses:
      # - URL construction for redirect and POST bindings
      # - XML document creation
      # - Message signing
      # - Parameter handling
      class MessageBuilder
        # Creates a new message builder instance
        # @param settings [RubySaml::Settings] Toolkit settings
        # @param id [String|nil] ID for the message (if nil, one will be generated)
        # @param relay_state [String|nil] RelayState parameter
        # @param params [Hash|nil] Additional parameters to include
        def initialize(settings, id: nil, relay_state: nil, params: nil)
          @settings = settings
          @id = id || generate_uuid
          @relay_state = relay_state
          @params = normalize_params(params)
        end

        # Returns the full URL for the SAML message
        # @return [String] URL for the SAML message
        def url
          binding_redirect? ? redirect_url : post_url
        end

        # Returns the body for POST requests
        # @return [Hash|nil] Body parameters for POST requests
        def body
          post_body unless binding_redirect?
        end

        # Constructs the redirect URL with parameters
        # @return [String] Full redirect URL with encoded parameters
        def redirect_url
          query_prefix = service_url.include?('?') ? '&' : '?'
          "#{service_url}#{query_prefix}#{URI.encode_www_form(build_payload(true))}"
        end
        memoize_method :redirect_url

        # Alias for service_url, used with POST binding
        # @return [String] Service URL for POST binding
        alias_method :post_url, :service_url
        memoize_method :post_url

        # Builds the POST request body
        # @return [Hash] POST request parameters
        def post_body
          build_payload(false)
        end
        memoize_method :post_params

        private

        attr_reader :settings,
                    :id,
                    :relay_state,
                    :params

        # Builds the payload for the SAML message
        # @param redirect [Boolean] Whether to build for redirect binding
        # @return [Hash] Parameters for the SAML message
        def build_payload(redirect)
          noko = build_xml_document
          sign_xml_document!(noko) unless redirect
          message_data = noko.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
          message_data = RubySaml::XML::Decoder.encode_message(message_data, compress: redirect)

          payload = { message_type => message_data }
          payload['RelayState'] = relay_state if relay_state

          if redirect && sign? && signing_key
            payload['SigAlg'] = signature_method
            signed_params = URI.encode_www_form(payload.slice(message_type, 'RelayState', 'SigAlg'))
            signature = signing_key.sign(hash_algorithm.new, signed_params)
            payload['Signature'] = Base64.strict_encode64(signature)
          end

          params.each do |key, value|
            payload[key] = value unless payload.key?(key)
          end

          payload
        end

        # Returns the attributes for the SAML root element
        # @return [Hash] A hash of attributes for the SAML root element
        def xml_root_attributes
          compact_blank!(
            'xmlns:samlp' => RubySaml::XML::NS_PROTOCOL,
            'xmlns:saml' => RubySaml::XML::NS_ASSERTION,
            'ID' => id,
            'IssueInstant' => utc_timestamp,
            'Version' => '2.0',
            'Destination' => service_url
          )
        end

        # Signs the XML document
        # @param noko [Nokogiri::XML::Document] The XML document to sign
        # @return [Nokogiri::XML::Document] The signed XML document
        def sign_xml_document!(noko)
          RubySaml::XML::DocumentSigner.sign_document!(
            noko,
            private_key,
            cert,
            signature_method,
            digest_method
          )
        end

        # Determines if the binding is redirect
        # @return [Boolean] True if the binding is redirect
        def binding_redirect?
          binding_type == Utils::BINDINGS[:redirect]
        end

        # Determines if the binding is POST
        # @return [Boolean] True if the binding is POST
        def binding_post?
          !binding_redirect?
        end

        # Returns the signing key
        # @return [OpenSSL::PKey::RSA] The signing key
        def signing_key
          @signing_key ||= settings.get_sp_signing_key
        end

        # Returns the signature method
        # @return [String] The signature method
        def signature_method
          @signature_method ||= settings.sp_signature_method
        end

        # Returns the hash algorithm
        # @return [Class] The hash algorithm class
        def hash_algorithm
          @hash_algorithm ||= RubySaml::XML.hash_algorithm(signature_method)
        end

        # Returns the digest method
        # @return [String] The digest method
        def digest_method
          @digest_method ||= settings.get_sp_digest_method
        end

        # Returns the UTC timestamp
        # @return [String] The UTC timestamp
        def utc_timestamp
          @utc_timestamp ||= RubySaml::Utils.utc_timestamp
        end

        # Generates a UUID
        # @return [String] A generated UUID
        def generate_uuid
          RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix)
        end

        # Normalizes parameters
        # @param params [Hash|nil] The parameters to normalize
        # @return [Hash] Normalized parameters
        def normalize_params(params)
          (params || {}).to_h do |key, value|
            next if value.nil? || value.empty?

            [key.to_s, value.to_s]
          end
        end

        # Removes blank values from a hash
        # @param hash [Hash] The hash to clean
        # @return [Hash] The hash with blank values removed
        def compact_blank!(hash)
          hash.reject! { |_, v| v.nil? || (v.respond_to?(:empty?) && v.empty?) }
          hash
        end

        # Abstract methods that must be implemented by subclasses
        %i[message_type binding_type service_url sign? build_xml_document].each do |method_name|
          define_method(method_name) do
            raise NoMethodError.new("Subclass must implement #{method_name}")
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      class MessageBuilder
        def initialize(settings, id: nil, relay_state: nil, params: nil)
          @settings = settings
          @id = id || generate_uuid
          @relay_state = relay_state
          @params = normalize_params(params)
        end

        def url
          binding_redirect? ? redirect_url : post_url
        end

        def body
          post_body unless binding_redirect?
        end

        def redirect_url
          query_prefix = service_url.include?('?') ? '&' : '?'
          "#{service_url}#{query_prefix}#{URI.encode_www_form(build_payload(true))}"
        end
        memoize_method :redirect_url

        alias_method :post_url, :service_url
        memoize_method :post_url

        def post_body
          build_payload(false)
        end
        memoize_method :post_params

        private

        attr_reader :settings,
                    :id,
                    :relay_state

        def build_payload(redirect)
          noko = build_xml_document
          sign_xml_document!(noko) unless redirect
          message_data = noko.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
          message_data = RubySaml::XML::Decoder.encode_message(message_data, compress: redirect)

          payload = { message_type => message_data }
          payload['RelayState'] = relay_state if relay_state

          if redirect && sign? && signing_key
            params['SigAlg'] = signature_method
            signed_params = url_encode(params.slice(message_type, 'RelayState', 'SigAlg'))
            signature = signing_key.sign(hash_algorithm.new, signed_params)
            params['Signature'] = Base64.strict_encode64(signature)
          end

          payload.reverse_merge!(params)
          payload
        end

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

        def sign_xml_document!(noko)
          RubySaml::XML::DocumentSigner.sign_document!(
            noko,
            private_key,
            cert,
            signature_method,
            digest_method
          )
        end

        def binding_redirect?
          binding_type == Utils::BINDINGS[:redirect]
        end

        def binding_post?
          !binding_redirect?
        end

        def signing_key
          @signing_key ||= settings.get_sp_signing_key
        end

        def signature_method
          @signature_method ||= settings.sp_signature_method
        end

        def hash_algorithm
          @hash_algorithm ||= RubySaml::XML.hash_algorithm(signature_method)
        end

        def digest_method
          @digest_method ||= settings.get_sp_digest_method
        end

        # Intentionally memoized
        def utc_timestamp
          @utc_timestamp ||= RubySaml::Utils.utc_timestamp
        end

        def generate_uuid
          RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix)
        end

        def normalize_params(params)
          (params || {}).to_h do |key, value|
            next if value.nil? || value.empty?

            [key.to_s, value.to_s]
          end
        end

        def compact_blank!(hash)
          hash.reject! { |_, v| v.nil? || (v.respond_to?(:empty?) && v.empty?) }
          hash
        end

        %i[message_type binding_type service_url sign? build_xml_document].each do |method_name|
          define_method(method_name) do
            raise NoMethodError.new("Subclass must implement #{method_name}")
          end
        end
      end
    end
  end
end

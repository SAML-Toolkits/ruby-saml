# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # Base builder for SAML messages
      class MessageBuilder
        def initialize(settings, uuid: nil, params: nil, relay_state: nil)
          @settings = settings
          @uuid = uuid || generate_uuid
          @relay_state = relay_state
        end

        def url
          binding_redirect? ? redirect_uri : post_uri
        end

        def params
          binding_redirect? ? nil : post_params
        end

        def redirect_url

        end
        memoize_method :redirect_url

        alias_method :post_url, :service_url

        def post_params

        end
        memoize_method :post_params



        # TODO:
        # if saml_settings.idp_sso_service_binding.end_with?('HTTP-POST')
        #   render json: { http_post_uri: saml_settings.idp_sso_service_url,
        #                  http_post_params: auth.create_params(saml_settings, auth_params) }
        # else
        #   render json: { http_redirect_uri: auth.create(saml_settings, auth_params) }
        # end



        # TODO: Add this method
        def extract_relay_state(relay_state, params)
          # relay_state = params[:RelayState] || params['RelayState']
          # if relay_state.nil?
          #   params.delete(:RelayState)
          #   params.delete('RelayState')
          # end
        end

        def url
          params_prefix = service_url.include?('?') ? '&' : '?'
          param_value = CGI.escape(url_params.delete(message_type))
          query = +"#{params_prefix}#{message_type}=#{param_value}"
          params.each_pair do |key, value|
            query << "&#{key}=#{CGI.escape(value.to_s)}"
          end
          service_url + query
        end
        memoize_method :url
        alias_method :create_url, :url

        def url_params
          # raw params
        end

        def url_query
          message = xml_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
          base64_message = RubySaml::XML::Decoder.encode_message(message, compress: binding_redirect?)
          message_params = { message_type => base64_message }
          message_params[:RelayState] = relay_state if relay_state
          message_params.merge(
            build_signature_params(
              base64_message,
              relay_state,
              binding_redirect,
              message_type
            )
          )
        end
        memoize_method :url_query

        def build_signature_params
          if binding_redirect && sign? && signing_key
            url_string = +"#{message_type}=#{CGI.escape(data)}"
            url_string << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
            url_string << "&SigAlg=#{CGI.escape(signature_method)}"
            url_string
            signature = signing_key.sign(signature_hash_algorithm.new, url_string)
            params['Signature'] = Base64.strict_encode64(signature)
          end
          params
        end

        def xml
          noko = build_xml_document
          sign_document!(noko)
          noko.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
        end
        memoize_method :xml
        alias_method :create_xml, :xml

        private

        attr_reader :settings,
                    :uuid,
                    :relay_state

        # def create_unsigned_xml
        #   create_xml_document(settings)
        # end

        def xml_root_attributes
          compact_blank!(
            'xmlns:samlp' => RubySaml::XML::NS_PROTOCOL,
            'xmlns:saml' => RubySaml::XML::NS_ASSERTION,
            'ID' => uuid,
            'IssueInstant' => RubySaml::Utils.utc_timestamp,
            'Version' => '2.0',
            'Destination' => service_url
          )
        end

        def sign_document!(noko)
          return unless sign?

          cert, private_key = settings.get_sp_signing_pair
          return noko unless binding_post? && sign? && private_key && cert

          RubySaml::XML::DocumentSigner.sign_document!(
            noko,
            private_key,
            cert,
            signature_method,
            digest_method
          )
        end

        def compact_blank!(hash)
          hash.reject! { |_, v| v.nil? || (v.respond_to?(:empty?) && v.empty?) }
          hash
        end

        # def xml_document
        #   raise NoMethodError.new('Subclass must implement binding_type')
        # end
        # TODO: add these
        # def binding_type(settings)
        #   raise NoMethodError.new('Subclass must implement binding_type')
        # end
        #
        # def service_url(settings)
        #   raise NoMethodError.new('Subclass must implement service_url')
        # end

        def generate_uuid
          RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix)
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

        def signature_hash_algorithm
          @signature_algorithm ||= RubySaml::XML.hash_algorithm(signature_method)
        end

        def digest_method
          @digest_method ||= settings.get_sp_digest_method
        end
      end
    end
  end
end

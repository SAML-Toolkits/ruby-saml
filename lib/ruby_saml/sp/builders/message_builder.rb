# frozen_string_literal: true

module RubySaml
  module Messages
    # Base builder for SP-initiated SAML messages
    class MessageBuilder < Message
      attr_accessor :uuid

      # TODO: REFACTOR TO HAVE THESE:
      # public methods:
      # - create_url
      # - create_url_params
      # - create_xml
      #
      # private methods:
      # - create_unsigned_xml
      # - ...



      # Create the LogoutResponse
      def create(settings,
                 old_request_id = nil,
                 old_status_message = nil,
                 old_relay_state = nil,
                 old_status_code = nil,
                 relay_state: nil,
                 request_id: nil,
                 status_code: nil,
                 status_message: nil)
        deprecate_positional_args(old_request_id, old_status_message, old_relay_state, old_status_code)

        @uuid = generate_uuid(settings)
        relay_state = process_relay_state(params)

        # LogoutResponse
        service_url = service_url(settings, :slo)
        raise SettingsError.new('Missing IdP SLO service URL') if service_url.nil? || service_url.empty?

        # LogoutRequest
        #   service_url = service_url(settings, :slo)
        #   raise SettingsError.new("Missing IdP SLO service URL") if service_url.nil? || service_url.empty?

        # AuthnRequest
        #   service_url = service_url(settings, :sso)
        #   raise SettingsError.new("Missing IdP SSO service URL") if service_url.nil? || service_url.empty?

        xml_doc = create_logout_response_xml(settings, request_id, logout_message, status_code)

        binding = binding_type(settings, :slo)
        params = build_params(
          settings, xml_doc, relay_state, 'SAMLResponse', :logout_responses_signed, binding
        )
        #   request_params = build_params(
        #     settings, xml_doc, relay_state, "SAMLRequest", :logout_requests_signed, binding
        #   )
        #   request_params = build_params(
        #     settings, xml_doc, relay_state, 'SAMLRequest', :authn_requests_signed, binding
        #   )

        build_url(settings, params, service_url, 'SAMLResponse')
      end

      private

      def deprecate_positional_args(old_request_id, old_status_message, old_relay_state, old_status_code)
        return if old_request_id.nil? && old_status_message.nil? && old_relay_state.nil? && old_status_code.nil?

        warn 'DEPRECATION WARNING: Positional arguments for RubySaml::Messages::MessageBuilder#create are deprecated. ' \
             'Please use keyword arguments instead.'
      end

      # Create URL with SAML parameters
      def build_url(params, service_url, param_name)
        raise ValidationError.new("Service URL cannot be nil") if service_url.nil? || service_url.empty?

        params_prefix = service_url.include?('?') ? '&' : '?'
        param_value = CGI.escape(params.delete(param_name))
        url_params = +"#{params_prefix}#{param_name}=#{param_value}"

        params.each_pair do |key, value|
          url_params << "&#{key}=#{CGI.escape(value.to_s)}"
        end

        service_url + url_params
      end

      # Process relay state from params
      def process_relay_state(params)
        relay_state = params[:RelayState] || params['RelayState']

        if relay_state.nil?
          params.delete(:RelayState)
          params.delete('RelayState')
        end

        relay_state
      end

      # Build signature parameters
      def build_signature_params(settings, base64_data, relay_state, binding_redirect, security_option)
        params = {}
        sp_signing_key = settings.get_sp_signing_key

        if binding_redirect && settings.security[security_option] && sp_signing_key
          params['SigAlg'] = settings.get_sp_signature_method
          url_string = build_query(
            type: @request_type,
            data: base64_data,
            relay_state: relay_state,
            sig_alg: params['SigAlg']
          )
          sign_algorithm = RubySaml::XML.hash_algorithm(settings.get_sp_signature_method)
          signature = sp_signing_key.sign(sign_algorithm.new, url_string)
          params['Signature'] = Base64.strict_encode64(signature)
        end

        params
      end

      # Create parameters for SAML request/response
      def create_params(settings, xml_doc, binding_redirect, relay_state, security_option, param_name)
        request_doc = xml_doc
        message = request_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)

        Logging.debug "Created #{param_name}: #{message}"

        @request_type = param_name
        base64_message = RubySaml::XML::Decoder.encode_message(message, compress: binding_redirect)
        message_params = { param_name => base64_message }

        signature_params = build_signature_params(
          settings,
          base64_message,
          relay_state,
          binding_redirect,
          security_option
        )

        params = {}
        params.merge!(signature_params)

        params.each_pair do |key, value|
          message_params[key] = value.to_s
        end

        message_params
      end

      # Build the Query String signature that will be used in the HTTP-Redirect binding
      # to generate the Signature
      # @param params [Hash] Parameters to build the Query String
      # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
      # @option params [String] :data Base64 encoded SAMLRequest or SAMLResponse
      # @option params [String] :relay_state The RelayState parameter
      # @option params [String] :sig_alg The SigAlg parameter
      # @return [String] The Query String
      def build_query(params)
        type, data, relay_state, sig_alg = params.values_at(:type, :data, :relay_state, :sig_alg)

        url_string = +"#{type}=#{CGI.escape(data)}"
        url_string << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
        url_string << "&SigAlg=#{CGI.escape(sig_alg)}"
        url_string
      end

      # Generate a UUID
      def generate_uuid(settings)
        RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix)
      end
    end
  end
end

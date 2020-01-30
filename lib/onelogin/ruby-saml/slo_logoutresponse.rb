require "onelogin/ruby-saml/logging"

require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/utils"
require "onelogin/ruby-saml/setting_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Logout Response (SLO SP initiated, Parser)
    #
    class SloLogoutresponse < SamlMessage

      # Logout Response ID
      attr_reader :uuid

      # Initializes the Logout Response. A SloLogoutresponse Object that is an extension of the SamlMessage class.
      # Asigns an ID, a random uuid.
      #
      def initialize
        @uuid = OneLogin::RubySaml::Utils.uuid
      end

      # Creates the Logout Response string.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
      # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
      # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
      # @return [String] Logout Request string that includes the SAMLRequest
      #
      def create(settings, request_id = nil, logout_message = nil, params = {})
        params = create_params(settings, request_id, logout_message, params)
        params_prefix = (settings.idp_slo_target_url =~ /\?/) ? '&' : '?'
        saml_response = CGI.escape(params.delete("SAMLResponse"))
        response_params = "#{params_prefix}SAMLResponse=#{saml_response}"
        params.each_pair do |key, value|
          response_params << "&#{key.to_s}=#{CGI.escape(value.to_s)}"
        end

        raise SettingError.new "Invalid settings, idp_slo_target_url is not set!" if settings.idp_slo_target_url.nil? or settings.idp_slo_target_url.empty?
        @logout_url = settings.idp_slo_target_url + response_params
      end

      # Creates the Get parameters for the logout response.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
      # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
      # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
      # @return [Hash] Parameters
      #
      def create_params(settings, request_id = nil, logout_message = nil, params = {})
        # The method expects :RelayState but sometimes we get 'RelayState' instead.
        # Based on the HashWithIndifferentAccess value in Rails we could experience
        # conflicts so this line will solve them.
        relay_state = params[:RelayState] || params['RelayState']

        if relay_state.nil?
          params.delete(:RelayState)
          params.delete('RelayState')
        end

        response_doc = create_logout_response_xml_doc(settings, request_id, logout_message)
        response_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        response = ""
        response_doc.write(response)

        Logging.debug "Created SLO Logout Response: #{response}"

        response = deflate(response) if settings.compress_response
        base64_response = encode(response)
        response_params = {"SAMLResponse" => base64_response}

        if settings.security[:logout_responses_signed] && !settings.security[:embed_sign] && settings.private_key
          params['SigAlg']    = settings.security[:signature_method]
          url_string = OneLogin::RubySaml::Utils.build_query(
            :type => 'SAMLResponse',
            :data => base64_response,
            :relay_state => relay_state,
            :sig_alg => params['SigAlg']
          )
          sign_algorithm = XMLSecurity::BaseDocument.new.algorithm(settings.security[:signature_method])
          signature = settings.get_sp_key.sign(sign_algorithm.new, url_string)
          params['Signature'] = encode(signature)
        end

        params.each_pair do |key, value|
          response_params[key] = value.to_s
        end

        response_params
      end

      # Creates the SAMLResponse String.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
      # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
      # @return [String] The SAMLResponse String.
      #
      def create_logout_response_xml_doc(settings, request_id = nil, logout_message = nil)
        document = create_xml_document(settings, request_id, logout_message)
        sign_document(document, settings)
      end

      def create_xml_document(settings, request_id = nil, logout_message = nil)
        time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

        response_doc = XMLSecurity::Document.new
        response_doc.uuid = uuid

        root = response_doc.add_element 'samlp:LogoutResponse', { 'xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol', "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = '2.0'
        root.attributes['InResponseTo'] = request_id unless request_id.nil?
        root.attributes['Destination'] = settings.idp_slo_target_url unless settings.idp_slo_target_url.nil? or settings.idp_slo_target_url.empty?

        if settings.sp_entity_id != nil
          issuer = root.add_element "saml:Issuer"
          issuer.text = settings.sp_entity_id
        end

        # add success message
        status = root.add_element 'samlp:Status'

        # success status code
        status_code = status.add_element 'samlp:StatusCode'
        status_code.attributes['Value'] = 'urn:oasis:names:tc:SAML:2.0:status:Success'

        # success status message
        logout_message ||= 'Successfully Signed Out'
        status_message = status.add_element 'samlp:StatusMessage'
        status_message.text = logout_message

        response_doc
      end

      def sign_document(document, settings)
        # embed signature
        if settings.security[:logout_responses_signed] && settings.private_key && settings.certificate && settings.security[:embed_sign]
          private_key = settings.get_sp_key
          cert = settings.get_sp_cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        document
      end

    end
  end
end

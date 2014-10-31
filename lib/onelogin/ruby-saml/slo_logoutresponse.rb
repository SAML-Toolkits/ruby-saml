module OneLogin
  module RubySaml
    class SloLogoutresponse < SamlMessage

      def create(settings, request, logout_message = nil, params = {})
        params = {} if params.nil?

        response_doc = create_logout_response_xml_doc(settings, request, logout_message)
        response_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        response = ''
        response_doc.write(response)

        Logging.debug "Created SLO Logout Response: #{response}"

        encoded_response   = encode_raw_saml(response, settings)
        params_prefix     = (settings.idp_slo_target_url =~ /\?/) ? '&' : '?'
        response_params    = "#{params_prefix}SAMLResponse=#{encoded_response}"

        params.each_pair do |key, value|
          response_params << "&#{key.to_s}=#{escape(value.to_s)}"
        end

        settings.idp_slo_target_url + response_params
      end

      def create_logout_response_xml_doc(settings, request, logout_message = nil)
        uuid = '_' + UUID.new.generate
        time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

        response_doc = REXML::Document.new

        root = response_doc.add_element 'samlp:LogoutResponse', { 'xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol' }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = '2.0'
        root.attributes['InResponseTo'] = request.id unless request.id.nil?
        root.attributes['Destination'] = settings.idp_slo_target_url unless settings.idp_slo_target_url.nil?

        # add success message
        status = root.add_element 'samlp:Status'

        # success status code
        status_code = status.add_element 'samlp:StatusCode'
        status_code.attributes['Value'] = 'urn:oasis:names:tc:SAML:2.0:status:Success'

        # success status message
        logout_message ||= 'Successfully Signed Out'
        status_message = status.add_element 'samlp:StatusMessage'
        status_message.text = logout_message

        if settings.issuer != nil
          issuer = root.add_element "saml:Issuer", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
          issuer.text = settings.issuer
        end

        response_doc
      end

    end
  end
end

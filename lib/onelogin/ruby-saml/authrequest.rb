require "base64"
require "zlib"
require "cgi"
require "onelogin/ruby-saml/utils"

module OneLogin
  module RubySaml

    class Authrequest
      # AuthNRequest ID
      attr_reader :uuid

      # Initializes the AuthNRequest. An Authrequest Object.
      # Asigns an ID, a random uuid.
      #
      def initialize
        @uuid = OneLogin::RubySaml::Utils.uuid
      end

      def create(settings, params = {})
        params = create_params(settings, params)
        params_prefix = (settings.idp_sso_target_url =~ /\?/) ? '&' : '?'
        saml_request = CGI.escape(params.delete("SAMLRequest"))
        request_params = "#{params_prefix}SAMLRequest=#{saml_request}"
        params.each_pair do |key, value|
          request_params << "&#{key.to_s}=#{CGI.escape(value.to_s)}"
        end
        raise "Invalid settings, idp_sso_target_url is not set!" if settings.idp_sso_target_url.nil?
        @login_url = settings.idp_sso_target_url + request_params
      end

      # Creates the Get parameters for the request.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
      # @return [Hash] Parameters
      #
      def create_params(settings, params={})
        # The method expects :RelayState but sometimes we get 'RelayState' instead.
        # Based on the HashWithIndifferentAccess value in Rails we could experience
        # conflicts so this line will solve them.
        relay_state = params[:RelayState] || params['RelayState']

        if relay_state.nil?
          params.delete(:RelayState)
          params.delete('RelayState')
        end

        request_doc = create_authentication_xml_doc(settings)
        request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        request = ""
        request_doc.write(request)

        Logging.debug "Created AuthnRequest: #{request}"

        request = Zlib::Deflate.deflate(request, 9)[2..-5] if settings.compress_request
        if Base64.respond_to?('strict_encode64')
          base64_request = Base64.strict_encode64(request)
        else
          base64_request = Base64.encode64(request).gsub(/\n/, "")
        end

        request_params = {"SAMLRequest" => base64_request}

        if settings.security[:authn_requests_signed] && !settings.security[:embed_sign] && settings.private_key
          params['SigAlg']    = settings.security[:signature_method]
          url_string = OneLogin::RubySaml::Utils.build_query(
            :type => 'SAMLRequest',
            :data => base64_request,
            :relay_state => relay_state,
            :sig_alg => params['SigAlg']
          )
          sign_algorithm = XMLSecurity::BaseDocument.new.algorithm(settings.security[:signature_method])
          signature = settings.get_sp_key.sign(sign_algorithm.new, url_string)
          if Base64.respond_to?('strict_encode64')
            params['Signature'] = Base64.strict_encode64(signature)
          else
            params['Signature'] = Base64.encode64(signature).gsub(/\n/, "")
          end
        end

        params.each_pair do |key, value|
          request_params[key] = value.to_s
        end

        request_params
      end

      def create_authentication_xml_doc(settings)
        document = create_xml_document(settings)
        sign_document(document, settings)
      end

      def create_xml_document(settings)
        time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

        request_doc = XMLSecurity::Document.new
        request_doc.uuid = uuid

        root = request_doc.add_element "samlp:AuthnRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol", "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = "2.0"
        root.attributes['Destination'] = settings.idp_sso_target_url unless settings.idp_sso_target_url.nil?
        root.attributes['IsPassive'] = settings.passive unless settings.passive.nil?
        root.attributes['ProtocolBinding'] = settings.protocol_binding unless settings.protocol_binding.nil?
        root.attributes['ForceAuthn'] = settings.force_authn unless settings.force_authn.nil?

        # Conditionally defined elements based on settings
        if settings.assertion_consumer_service_url != nil
          root.attributes["AssertionConsumerServiceURL"] = settings.assertion_consumer_service_url
        end
        if settings.sp_entity_id != nil
          issuer = root.add_element "saml:Issuer"
          issuer.text = settings.sp_entity_id
        end

        if settings.name_identifier_value_requested != nil
          subject = root.add_element "saml:Subject"

          nameid = subject.add_element "saml:NameID"
          nameid.attributes['Format'] = settings.name_identifier_format if settings.name_identifier_format
          nameid.text = settings.name_identifier_value_requested

          subject_confirmation = subject.add_element "saml:SubjectConfirmation"
          subject_confirmation.attributes['Method'] = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        end

        if settings.name_identifier_format != nil
          root.add_element "samlp:NameIDPolicy", {
              "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
              # Might want to make AllowCreate a setting?
              "AllowCreate" => "true",
              "Format" => settings.name_identifier_format
          }
        end

        # BUG fix here -- if an authn_context is defined, add the tags with an "exact"
        # match required for authentication to succeed.  If this is not defined,
        # the IdP will choose default rules for authentication.  (Shibboleth IdP)
        if settings.authn_context != nil
          requested_context = root.add_element "samlp:RequestedAuthnContext", {
            "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
            "Comparison" => "exact",
          }
          class_ref = requested_context.add_element "saml:AuthnContextClassRef", {
            "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
          }
          class_ref.text = settings.authn_context
        end
        request_doc
      end

      def sign_document(document, settings)
        # embed signature
        if settings.security[:authn_requests_signed] && settings.private_key && settings.certificate && settings.security[:embed_sign]
          private_key = settings.get_sp_key
          cert = settings.get_sp_cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        document
      end

    end
  end
end

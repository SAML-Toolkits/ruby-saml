require "uuid"

require "onelogin/ruby-saml/logging"

module OneLogin
  module RubySaml
  include REXML
    class Authrequest < SamlMessage

      attr_reader :uuid # Can be obtained if neccessary

      def initialize
        @uuid = "_" + UUID.new.generate
      end

      def create(settings, params = {})
        params = create_params(settings, params)
        params_prefix = (settings.idp_sso_target_url =~ /\?/) ? '&' : '?'
        saml_request = CGI.escape(params.delete("SAMLRequest"))
        request_params = "#{params_prefix}SAMLRequest=#{saml_request}"
        params.each_pair do |key, value|
          request_params << "&#{key.to_s}=#{CGI.escape(value.to_s)}"
        end
        @login_url = settings.idp_sso_target_url + request_params
      end

      def create_params(settings, params={})
        params = {} if params.nil?

        request_doc = create_authentication_xml_doc(settings)
        request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        request = ""
        request_doc.write(request)

        Logging.debug "Created AuthnRequest: #{request}"

        request = deflate(request) if settings.compress_request
        base64_request = encode(request)
        request_params = {"SAMLRequest" => base64_request}

        if settings.security[:authn_requests_signed] && !settings.security[:embed_sign] && settings.private_key
          params['SigAlg']    = XMLSecurity::Document::SHA1
          url_string          = "SAMLRequest=#{CGI.escape(base64_request)}"
          url_string         += "&RelayState=#{CGI.escape(params['RelayState'])}" if params['RelayState']
          url_string         += "&SigAlg=#{CGI.escape(params['SigAlg'])}"
          private_key         = settings.get_sp_key()
          signature           = private_key.sign(XMLSecurity::BaseDocument.new.algorithm(settings.security[:signature_method]).new, url_string)
          params['Signature'] = encode(signature)
        end

        params.each_pair do |key, value|
          request_params[key] = value.to_s
        end

        request_params
      end

      def create_authentication_xml_doc(settings)
        time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        request_doc = XMLSecurity::Document.new
        request_doc.uuid = uuid

        root = request_doc.add_element "samlp:AuthnRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol", "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = "2.0"
        root.attributes['Destination'] = settings.idp_sso_target_url unless settings.idp_sso_target_url.nil?
        root.attributes['IsPassive'] = settings.passive unless settings.passive.nil?
        root.attributes['ProtocolBinding'] = settings.protocol_binding unless settings.protocol_binding.nil?
        root.attributes["AttributeConsumingServiceIndex"] = settings.attributes_index unless settings.attributes_index.nil?
        root.attributes['ForceAuthn'] = settings.force_authn unless settings.force_authn.nil?

        # Conditionally defined elements based on settings
        if settings.assertion_consumer_service_url != nil
          root.attributes["AssertionConsumerServiceURL"] = settings.assertion_consumer_service_url
        end
        if settings.issuer != nil
          issuer = root.add_element "saml:Issuer"
          issuer.text = settings.issuer
        end
        if settings.name_identifier_format != nil
          root.add_element "samlp:NameIDPolicy", {
              # Might want to make AllowCreate a setting?
              "AllowCreate" => "true",
              "Format" => settings.name_identifier_format
          }
        end

        if settings.authn_context || settings.authn_context_decl_ref

          if settings.authn_context_comparison != nil
            comparison = settings.authn_context_comparison
          else
            comparison = 'exact'
          end

          requested_context = root.add_element "samlp:RequestedAuthnContext", {
            "Comparison" => comparison,
          }

          if settings.authn_context != nil
            class_ref = requested_context.add_element "saml:AuthnContextClassRef"
            class_ref.text = settings.authn_context
          end
          # add saml:AuthnContextDeclRef element
          if settings.authn_context_decl_ref != nil
            class_ref = requested_context.add_element "saml:AuthnContextDeclRef"
            class_ref.text = settings.authn_context_decl_ref
          end
        end

        if settings.proxy_count || settings.idp_list || settings.requester_id
          proxy_count_attribute = if settings.proxy_count
            {
              'ProxyCount' => settings.proxy_count.to_s
            }
          end

          scoping = root.add_element 'samlp:Scoping', proxy_count_attribute

          if settings.idp_list
            idp_list_element = scoping.add_element 'samlp:IDPList'
            settings.idp_list.each do |idp_entry|
              idp_list_element.add_element 'samlp:IDPEntry', {
                'Name' => idp_entry['name'],
                'ProviderID' => idp_entry['provider_id']
              }
            end
          end

          if settings.requester_id
            requester_id = scoping.add_element 'samlp:RequesterID'
            requester_id.text = settings.requester_id
          end
        end

        # embebed sign
        if settings.security[:authn_requests_signed] && settings.private_key && settings.certificate && settings.security[:embed_sign] 
          private_key = settings.get_sp_key()
          cert = settings.get_sp_cert()
          request_doc.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        request_doc
      end

    end
  end
end

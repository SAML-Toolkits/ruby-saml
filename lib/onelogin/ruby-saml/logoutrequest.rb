require "uuid"

require "onelogin/ruby-saml/logging"

module OneLogin
  module RubySaml
    class Logoutrequest < SamlMessage

      attr_reader :uuid # Can be obtained if neccessary

      def initialize
        @uuid = "_" + UUID.new.generate
      end

      def create(settings, params={})
        params = create_params(settings, params)
        params_prefix = (settings.idp_slo_target_url =~ /\?/) ? '&' : '?'
        saml_request = CGI.escape(params.delete("SAMLRequest"))
        request_params = "#{params_prefix}SAMLRequest=#{saml_request}"
        params.each_pair do |key, value|
          request_params << "&#{key.to_s}=#{CGI.escape(value.to_s)}"
        end
        @logout_url = settings.idp_slo_target_url + request_params
      end

      def create_params(settings, params={})
        params = {} if params.nil?

        request_doc = create_logout_request_xml_doc(settings)
        request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        request = ""
        request_doc.write(request)

        Logging.debug "Created SLO Logout Request: #{request}"

        request = deflate(request) if settings.compress_request
        base64_request = encode(request)
        request_params = {"SAMLRequest" => base64_request}

        if settings.security[:logout_requests_signed] && !settings.security[:embed_sign] && settings.private_key
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

      def create_logout_request_xml_doc(settings)
        time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        request_doc = XMLSecurity::Document.new
        request_doc.uuid = uuid

        root = request_doc.add_element "samlp:LogoutRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol", "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = "2.0"
        root.attributes['Destination'] = settings.idp_slo_target_url  unless settings.idp_slo_target_url.nil?

        if settings.issuer
          issuer = root.add_element "saml:Issuer"
          issuer.text = settings.issuer
        end

        name_id = root.add_element "saml:NameID"
        if settings.name_identifier_value
          name_id.attributes['NameQualifier'] = settings.sp_name_qualifier if settings.sp_name_qualifier
          name_id.attributes['Format'] = settings.name_identifier_format if settings.name_identifier_format
          name_id.text = settings.name_identifier_value
        else
          # If no NameID is present in the settings we generate one
          name_id.text = "_" + UUID.new.generate
          name_id.attributes['Format'] = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        end

        if settings.sessionindex
          sessionindex = root.add_element "samlp:SessionIndex"
          sessionindex.text = settings.sessionindex
        end

        # embebed sign
        if settings.security[:logout_requests_signed] && settings.private_key && settings.certificate && settings.security[:embed_sign]
          private_key = settings.get_sp_key()
          cert = settings.get_sp_cert()
          request_doc.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        request_doc
      end
    end
  end
end

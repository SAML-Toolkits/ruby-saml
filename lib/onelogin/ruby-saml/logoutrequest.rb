require "base64"
require "zlib"
require "cgi"
require 'rexml/document'
require "onelogin/ruby-saml/utils"
require "onelogin/ruby-saml/setting_error"

module OneLogin
  module RubySaml

    class Logoutrequest

      attr_reader :uuid # Can be obtained if neccessary

      def initialize
        @uuid = OneLogin::RubySaml::Utils.uuid
      end

      def create(settings, params={})
        params = create_params(settings, params)
        params_prefix = (settings.idp_slo_target_url =~ /\?/) ? '&' : '?'
        saml_request = CGI.escape(params.delete("SAMLRequest"))
        request_params = "#{params_prefix}SAMLRequest=#{saml_request}"
        params.each_pair do |key, value|
          request_params << "&#{key.to_s}=#{CGI.escape(value.to_s)}"
        end
        raise SettingError.new "Invalid settings, idp_slo_target_url is not set!" if settings.idp_slo_target_url.nil? or settings.idp_slo_target_url.empty?
        @logout_url = settings.idp_slo_target_url + request_params
      end

      # Creates the Get parameters for the logout request.
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

        request_doc = create_logout_request_xml_doc(settings)
        request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        request = ""
        request_doc.write(request)

        Logging.debug "Created SLO Logout Request: #{request}"

        request = Zlib::Deflate.deflate(request, 9)[2..-5] if settings.compress_request
        if Base64.respond_to?('strict_encode64')
          base64_request = Base64.strict_encode64(request)
        else
          base64_request = Base64.encode64(request).gsub(/\n/, "")
        end
        request_params = {"SAMLRequest" => base64_request}

        if settings.security[:logout_requests_signed] && !settings.security[:embed_sign] && settings.private_key
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

      # Creates the SAMLRequest String.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @return [String] The SAMLRequest String.
      #
      def create_logout_request_xml_doc(settings)
        document = create_xml_document(settings)
        sign_document(document, settings)
      end

      def create_xml_document(settings, request_doc=nil)
        time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

        if request_doc.nil?
          request_doc = XMLSecurity::Document.new
          request_doc.uuid = uuid
        end

        root = request_doc.add_element "samlp:LogoutRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = "2.0"
        root.attributes['Destination'] = settings.idp_slo_target_url  unless settings.idp_slo_target_url.nil? or settings.idp_slo_target_url.empty?

        if settings.sp_entity_id
          issuer = root.add_element "saml:Issuer", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
          issuer.text = settings.sp_entity_id
        end

        if settings.name_identifier_value
          name_id = root.add_element "saml:NameID", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
          name_id.attributes['NameQualifier'] = settings.sp_name_qualifier if settings.sp_name_qualifier
          name_id.attributes['Format'] = settings.name_identifier_format if settings.name_identifier_format
          name_id.text = settings.name_identifier_value
        end

        if settings.sessionindex
          sessionindex = root.add_element "samlp:SessionIndex", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
          sessionindex.text = settings.sessionindex
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
        if settings.security[:logout_requests_signed] && settings.private_key && settings.certificate && settings.security[:embed_sign]
          private_key = settings.get_sp_key
          cert = settings.get_sp_cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        document
      end

      # Leave due compatibility
      def create_unauth_xml_doc(settings, params)
        request_doc = ReXML::Document.new
        create_xml_document(settings, request_doc)
      end
    end
  end
end

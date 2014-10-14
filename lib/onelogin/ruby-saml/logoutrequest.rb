require "base64"
require "uuid"
require "zlib"
require "cgi"

module OneLogin
  module RubySaml
    include REXML
    class Logoutrequest
      
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


      attr_reader  :request # Can be obtained if neccessary
      attr_accessor :params

      def initialize(request, doc, settings)
        @request = request
        @document = doc
        @settings = settings
      end

      def self.create(settings, params={})
        request_doc = create_unauth_xml_doc(settings, params)
        request = ""
        request_doc.write(request)
        req = new(request, request_doc, settings)
        req.params = params
        return req
      end

      def encoded_message
        deflated_request  = Zlib::Deflate.deflate(@request, 9)[2..-5]
        msg = Base64.encode64(deflated_request)
        msg
      end

      def logout_url
        params_prefix     = (@settings.idp_slo_target_url =~ /\?/) ? '&' : '?'
        request_params    = "#{params_prefix}SAMLRequest=#{CGI.escape(encoded_message.gsub("\n",'').gsub("\r",''))}"

        @params.each_pair do |key, value|
          request_params << "&#{key}=#{CGI.escape(value.to_s)}"
        end

        @settings.idp_slo_target_url + request_params

      end

      def decode(encoded)
        Base64.decode64(encoded)
      end

      def inflate(deflated)
        zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        zlib.inflate(deflated)
      end

      def decode_raw_request(request)
        if request =~ /^</
          return request
        elsif (decoded  = decode(request)) =~ /^</
          return decoded
        elsif (inflated = inflate(decoded)) =~ /^</
          return inflated
        end

        raise "Couldn't decode SAMLRequest"
      end

      def self.parse(request, settings = nil)
        request_doc = XMLSecurity::RequestDocument.new(decode_raw_request(request))
        new(request, request_doc, settings)
      end


      def self.create_unauth_xml_doc(settings, params)

        uuid = "_" + UUID.new.generate
        time = Time.new().strftime("%Y-%m-%dT%H:%M:%S")+"Z"

        request_doc = XMLSecurity::RequestDocument.new
        root = request_doc.add_element "samlp:LogoutRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] =   time
        root.attributes['Version'] = "2.0"

        if settings.issuer
          issuer = root.add_element "saml:Issuer", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
          issuer.text = settings.issuer
        end

        if settings.name_identifier_value
          name_id = root.add_element "saml:NameID", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
          name_id.attributes['NameQualifier'] = settings.sp_name_qualifier if settings.sp_name_qualifier
          name_id.attributes['Format'] = settings.name_identifier_format if settings.name_identifier_format
          name_id.text = settings.name_identifier_value
        else
          raise ValidationError.new("Missing required name identifier")
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

        if settings.sign_request && settings.private_key && settings.certificate
          request_doc.sign_document(settings.private_key, settings.certificate, settings.signature_method, settings.digest_method)
        end

        request_doc
      end


      def uuid
        @uuid ||= begin
          node = REXML::XPath.first(@document, "/p:LogoutRequest", { "p" => PROTOCOL})
          node.nil? ? nil : node.attributes['ID']
        end
      end

    end
  end
end

require "xml_security"
require "time"
require "base64"
require "zlib"

module OneLogin
  module RubySaml
    class Logoutresponse

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"

      # For API compability, this is mutable.
      attr_accessor :settings

      attr_reader :document
      attr_reader :response
      attr_reader :options

      #
      # In order to validate that the response matches a given request, append
      # the option:
      #   :matches_request_id => REQUEST_ID
      #
      # It will validate that the logout response matches the ID of the request.
      # You can also do this yourself through the in_response_to accessor.
      #
      def initialize(response, document, settings = nil, options = {})
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        @settings = settings
        @options = options
        @response = response
        @document = document
      end


      def self.parse(response, settings  = nil, options = {})
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        resp = decode_raw_response(response)
        document = XMLSecurity::SignedDocument.new(resp)

        new(resp, document, settings, options)
      end


      def encode_message
        resp = @response

        deflated_resp  = Zlib::Deflate.deflate(resp, 9)[2..-5]
        base64_resp    = Base64.encode64(deflated_resp)

        return base64_resp
      end


      def logout_url
        params_prefix     = (@settings.idp_slo_target_url =~ /\?/) ? '&' : '?'
        request_params    = "#{params_prefix}SAMLResponse=#{encoded_message}"

        params.each_pair do |key, value|
          request_params << "&#{key}=#{CGI.escape(value.to_s)}"
        end
        @settings.idp_slo_target_url + request_params
      end

      def self.create(settings, params={}, status_code=STATUS_SUCCESS, status_message="Logout Successful")
       doc = create_unauth_xml_doc(settings, params, status_code,status_message)
       resp = ""
       doc.write(resp)

       newl(resp, doc, settings, params)
      end

      def self.create_unauth_xml_doc(settings, params={}, status_code = STATUS_SUCCESS, status_message="Logout Successful")

        time = Time.new().strftime("%Y-%m-%dT%H:%M:%S")+"Z"

        response_doc = XMLSecurity::RequestDocument.new
        root = response_doc.add_element "samlp:LogoutResponse", { "xmlns:samlp" => PROTOCOL, "xmlns:saml" => ASSERTION }
        uuid = "_" + UUID.new.generate
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] =   time
        root.attributes['Version'] = "2.0"

        if settings.idp_slo_target_url
          root.attributes['Destination'] = idp_slo_target_url
        end

        if params.key? :in_response_to
          root.attributes['InResponseTo'] = params[:in_response_to]
        end


        if settings.issuer
          issuer = root.add_element "saml:Issuer", { "xmlns:saml" => ASSERTION}
          issuer.text = settings.issuer
        else
          fail ArgumentError, "No issuer supplied"
        end

        if success
          status = root.add_element "samlp:Status", { "xmlns:samlp" => PROTOCOL}
          status.add_element "samlp:StatusCode", { "xmlns:samlp" => PROTOCOL, "Value" => status_code}
          status.add_element "samlp:Message", { "xmlns:samlp" => PROTOCOL, "Value" => status_message}
        else

        end


      end

      def validate!
        validate(false)
      end

      def validate(soft = true)
        return false unless valid_saml?(soft) && valid_state?(soft)

        valid_in_response_to?(soft) && valid_issuer?(soft) && success?(soft)
      end

      def success?(soft = true)
        unless status_code == STATUS_SUCCESS
          return soft ? false : validation_error("Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <#@status_code> ")
        end
        true
      end

      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= REXML::XPath.first(document, "/p:LogoutResponse/a:Assertion/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      private

      def self.decode(encoded)
        Base64.decode64(encoded)
      end

      def self.inflate(deflated)
        zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        zlib.inflate(deflated)
      end

      def self.decode_raw_response(response)
        if response =~ /^</
          return response
        elsif (decoded  = decode(response)) =~ /^</
          return decoded
        elsif (inflated = inflate(decoded)) =~ /^</
          return inflated
        end

        raise "Couldn't decode SAMLResponse"
      end

      def valid_saml?(soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml20protocol_schema.xsd'))
          @xml = Nokogiri::XML(self.document.to_s)
        end
        if soft
          @schema.validate(@xml).map{ return false }
        else
          @schema.validate(@xml).map{ |error| validation_error("#{error.message}\n\n#{@xml.to_s}") }
        end
      end

      def valid_state?(soft = true)
        if response.empty?
          return soft ? false : validation_error("Blank response")
        end

        if settings.nil?
          return soft ? false : validation_error("No settings on response")
        end

        if settings.issuer.nil?
          return soft ? false : validation_error("No issuer in settings")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def valid_in_response_to?(soft = true)
        return true unless self.options.has_key? :matches_request_id

        unless self.options[:matches_request_id] == in_response_to
          return soft ? false : validation_error("Response does not match the request ID, expected: <#{self.options[:matches_request_id]}>, but was: <#{in_response_to}>")
        end

        true
      end

      def valid_issuer?(soft = true)
        unless URI.parse(issuer) == URI.parse(self.settings.issuer)
          return soft ? false : validation_error("Doesn't match the issuer, expected: <#{self.settings.issuer}>, but was: <#{issuer}>")
        end
        true
      end

      def validation_error(message)
        raise ValidationError.new(message)
      end
    end
  end
end

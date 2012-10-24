require "xml_security"
require "time"

module Onelogin
  module Saml
    class Logoutresponse

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

      # For API compability, this is mutable.
      attr_accessor :settings

      attr_reader :document
      attr_reader :options
      attr_reader :response
      attr_reader :in_response_to, :issuer

      #
      # In order to validate that the response matches a given request, append
      # the option:
      #   :matches_request_id => REQUEST_ID
      #
      # It will validate that the logout response matches the ID of the request.
      # You can also do this yourself through the in_response_to accessor.
      #
      def initialize(response, settings = nil, options = {})
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        self.settings = settings

        @options = options
        @response = response

        if response =~ /</
          @response = response
        else
          @response = Base64.decode64(response)
        end

        begin
          @document = XMLSecurity::SignedDocument.new(response)
        rescue REXML::ParseException => e
          raise e
        end

        parse_logoutresponse
      end

      def validate!
        validate(false)
      end

      def validate(soft = true)
        return false unless valid_saml?(soft) && valid_state?(soft)

        valid_in_response_to?(soft) && valid_issuer?(soft) && success?
      end

      def success?
        @status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
      end

      private

      def parse_logoutresponse
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= REXML::XPath.first(document, "/p:LogoutResponse/a:Assertion/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      def valid_saml?(soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml20protocol_schema.xsd'))
          @xml = Nokogiri::XML(self.document.to_s)
        end
        if soft
          @schema.validate(@xml).map{ return false }
        else
          @schema.validate(@xml).map{ |error| raise(Exception.new("#{error.message}\n\n#{@xml.to_s}")) }
        end
      end

      def valid_state?(soft = true)
        if response.empty?
          return soft ? false : ValidationError.new("Blank response")
        end

        if settings.nil?
          return soft ? false : ValidationError.new("No settings on response")
        end

        if settings.issuer.nil?
          return soft ? false : ValidationError.new("No issuer in settings")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : ValidationError.new("No fingerprint or certificate on settings")
        end

        true
      end

      def valid_in_response_to?(soft = true)
        return true unless self.options.has_key? :matches_request_id

        unless self.options[:matches_request_id] == in_response_to
          return soft ? false : ValidationError.new("Response does not match the request ID, expected: <#{self.options[:matches_request_id]}>, but was: <#{in_response_to}>")
        end

        true
      end

      def valid_issuer?(soft = true)
        unless issuer == self.settings.issuer
          return soft ? false : ValidationError.new("Doesn't match the issuer, expected: <#{self.settings.issuer}>, but was: <#{issuer}>")
        end
        true
      end

    end
  end
end
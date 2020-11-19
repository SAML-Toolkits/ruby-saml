require "xml_security"
require "time"

module OneLogin
  module RubySaml
    class Logoutresponse

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

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
      def initialize(response, settings = nil, options = {})
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        self.settings = settings

        @options = options
        @response = OneLogin::RubySaml::Utils.decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response)
      end

      def validate!
        validate(false)
      end

      def validate(soft = true)
        return false unless validate_structure(soft)

        valid_in_response_to?(soft) && valid_issuer?(soft) && success?(soft)
      end

      def success?(soft = true)
        unless status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
          return soft ? false : validation_error("Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <#@status_code> ")
        end
        true
      end

      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          Utils.element_text(node)
        end
      end

      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      private

      def validate_structure(soft = true)
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

      def valid_in_response_to?(soft = true)
        return true unless self.options.has_key? :matches_request_id

        unless self.options[:matches_request_id] == in_response_to
          return soft ? false : validation_error("Response does not match the request ID, expected: <#{self.options[:matches_request_id]}>, but was: <#{in_response_to}>")
        end

        true
      end

      def valid_issuer?(soft = true)
        return true if settings.nil? || settings.idp_entity_id.nil? || issuer.nil?

        unless OneLogin::RubySaml::Utils.uri_match?(issuer, settings.idp_entity_id)
          return soft ? false : validation_error("Doesn't match the issuer, expected: <#{self.settings.idp_entity_id}>, but was: <#{issuer}>")
        end
        true
      end

      def validation_error(message)
        raise ValidationError.new(message)
      end
    end
  end
end

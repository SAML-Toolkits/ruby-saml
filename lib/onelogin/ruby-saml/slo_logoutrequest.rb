require "xml_security"
require "time"

# Only supports SAML 2.0
# SAML2 Logout Request (SLO IdP initiated, Parser)
module OneLogin
  module RubySaml
    class SloLogoutrequest

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

      # OneLogin::RubySaml::Settings Toolkit settings
      attr_accessor :settings

      attr_reader :document
      attr_reader :request
      attr_reader :options

      def initialize(request, settings = nil, options = {})
        raise ArgumentError.new("Request cannot be nil") if request.nil?
        self.settings = settings

        @options = options
        @request = OneLogin::RubySaml::Utils.decode_raw_saml(request)
        @document = XMLSecurity::SignedDocument.new(@request)
      end

      def validate!
        validate(false)
      end

      def validate(soft = true)
        return false unless validate_structure(soft)

        valid_issuer?(soft)
      end

      def name_id
        @name_id ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
          Utils.element_text(node)
        end
      end

      alias_method :nameid, :name_id

      def name_id_format
        @name_id_node ||= REXML::XPath.first(document, "/p:LogoutRequest/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
        @name_id_format ||=
          if @name_id_node && @name_id_node.attribute("Format")
            @name_id_node.attribute("Format").value
          end
      end

      alias_method :nameid_format, :name_id_format

      def id
        @id ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest", { "p" => PROTOCOL } )
          node.nil? ? nil : node.attributes['ID']
        end
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          Utils.element_text(node)
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

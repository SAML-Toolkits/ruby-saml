require "xml_security"
require "time"

module Onelogin::Saml
  class Response
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :response, :document, :logger, :settings, :original

    def initialize(response)
      raise ArgumentError.new("Response cannot be nil") if response.nil?
      self.response = response
      self.document = XMLSecurity::SignedDocument.new(Base64.decode64(response))
    end

    def is_valid?
      return false if response.empty?
      return false if settings.nil?
      return false if settings.idp_cert_fingerprint.nil?
      return false if !check_conditions

      document.validate(settings.idp_cert_fingerprint, logger)
    end

    # The value of the user identifier as designated by the initialization request response
    def name_id
      @name_id ||= begin
        node = REXML::XPath.first(document, "/p:Response/a:Assertion[@ID='#{document.signed_element_id[1,document.signed_element_id.size]}']/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
        node.nil? ? nil : node.text
      end
    end

    def check_conditions
      return true if conditions.nil?

      not_before = parse_time(conditions, "NotBefore")
      return false if not_before && Time.now.utc < not_before

      not_on_or_after = parse_time(conditions, "NotOnOrAfter")
      return false if not_on_or_after && Time.now.utc >= not_on_or_after

      true
    end

    # A hash of alle the attributes with the response. Assuming there is only one value for each key
    def attributes
      @attr_statements ||= begin
        result = {}

        stmt_element = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AttributeStatement", { "p" => PROTOCOL, "a" => ASSERTION })
        return {} if stmt_element.nil?

        stmt_element.elements.each do |attr_element|
          name  = attr_element.attributes["Name"]
          value = attr_element.elements.first.text

          result[name] = value
        end

        result.keys.each do |key|
          result[key.intern] = result[key]
        end

        result
      end
    end

    # When this user session should expire at latest
    def session_expires_at
      @expires_at ||= begin
        node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AuthnStatement", { "p" => PROTOCOL, "a" => ASSERTION })
        parse_time(node, "SessionNotOnOrAfter")
      end
    end

    # Conditions (if any) for the assertion to run
    def conditions
      @conditions ||= begin
        REXML::XPath.first(document, "/p:Response/a:Assertion[@ID='#{document.signed_element_id[1,document.signed_element_id.size]}']/a:Conditions", { "p" => PROTOCOL, "a" => ASSERTION })
      end
    end

    private

    def parse_time(node, attribute)
      if node && node.attributes[attribute]
        Time.parse(node.attributes[attribute])
      end
    end
  end
end

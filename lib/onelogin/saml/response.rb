require "xml_security"
require "time"

module Onelogin::Saml
  class Response
    attr_accessor :response, :document, :logger, :settings, :namespace

    def initialize(response)
      raise ArgumentError.new("Response cannot be nil") if response.nil?
      self.response  = response
      self.document  = XMLSecurity::SignedDocument.new(Base64.decode64(response))
      self.namespace = "saml"

      if document.elements["/#{namespace}p:Response/"].nil?
        self.namespace = "saml2"
      end
    end

    def is_valid?
      return false if response.empty?
      return false if settings.nil?
      return false if settings.idp_cert_fingerprint.nil?

      document.validate(settings.idp_cert_fingerprint, logger)
    end

    # The value of the user identifier as designated by the initialization request response
    def name_id
      @name_id ||= document.elements["/#{namespace}p:Response/#{namespace}:Assertion/#{namespace}:Subject/#{namespace}:NameID"].text
    end

    # A hash of alle the attributes with the response. Assuming there is onlye one value for each key
    def attributes
      saml_attribute_statements = document.elements["/#{namespace}p:Response/#{namespace}:Assertion/#{namespace}:AttributeStatement"].elements
      statements = saml_attribute_statements.map do |child|
        child.attributes.map do |key, attribute|
          [attribute, child.elements.first.text]
        end
      end

      hash = Hash[statements.flatten(1)]
      @attributes ||= make_hash_access_indiferent(hash)
    end

    # When this user session should expire at latest
    def session_expires_at
      @expires_at ||= Time.parse(document.elements["/#{namespace}p:Response/#{namespace}:Assertion/#{namespace}:AuthnStatement"].attributes["SessionNotOnOrAfter"])
    end

  private

    def make_hash_access_indiferent(hash)
      sym_hash = {}
      hash.each  do |key, value|
        sym_hash[key.intern] = value
      end

      sym_hash.merge(hash)
    end
  end
end
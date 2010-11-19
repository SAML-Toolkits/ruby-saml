require "rexml/document"
require "xml_sec" 
require "time"

module Onelogin::Saml
  class Response
    attr_accessor :response, :document, :logger, :settings

    def initialize(response)
      raise ArgumentError.new("Response cannot be nil") if response.nil?
      self.response = response
      self.document = XMLSecurity::SignedDocument.new(Base64.decode64(response))
    end

    def is_valid?
      return false if response.empty?
      return false if settings.nil?
      return false if settings.idp_cert_fingerprint.nil?

      document.validate(settings.idp_cert_fingerprint, logger)
    end

    # The value of the user identifier as designated by the initialization request response
    def name_id
      @name_id ||= document.elements["/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"].text
    end

    # When this user session should expire at latest
    def session_expires_at
      @expires_at ||= Time.parse(document.elements["/samlp:Response/saml:Assertion/saml:AuthnStatement"].attributes["SessionNotOnOrAfter"])
    end
  end
end
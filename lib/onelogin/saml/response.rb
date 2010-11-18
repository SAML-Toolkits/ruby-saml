require "rexml/document"
require "xml_sec" 

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

    def name_id
      document.elements["/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"].text
    end
  end
end
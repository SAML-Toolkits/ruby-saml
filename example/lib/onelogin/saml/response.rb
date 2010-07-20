require "rexml/document"
require "xml_sec" 

module Onelogin::Saml
  class Response
    def initialize(response)
      @response = response
      @document = XMLSecurity::SignedDocument.new(Base64.decode64(@response))
    end
    
    def logger=(val)
      @logger = val
    end
    
    def settings=(_settings)
      @settings = _settings
    end
    
    def is_valid?
      unless @response.blank?
        @document.validate(@settings.idp_cert_fingerprint, @logger) unless !@settings.idp_cert_fingerprint
      end
    end

    def name_id
      @document.elements["/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"].text
    end
  end
end
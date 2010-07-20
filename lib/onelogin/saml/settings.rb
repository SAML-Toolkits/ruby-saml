module Onelogin::Saml
  class Settings
    def assertion_consumer_service_url
      @assertion_consumer_service_url
    end
    def assertion_consumer_service_url=(val)
      @assertion_consumer_service_url = val
    end
    
    def issuer
      @issuer
    end
    def issuer=(val)
      @issuer = val
    end
    
    def sp_name_qualifier
      @sp_name_qualifier
    end
    def sp_name_qualifier=(val)
      @sp_name_qualifier = val
    end
    
    def idp_sso_target_url
      @idp_sso_target_url
    end
    def idp_sso_target_url=(val)
      @idp_sso_target_url = val
    end
    
    def idp_cert_fingerprint
      @idp_cert_fingerprint
    end
    def idp_cert_fingerprint=(val)
      @idp_cert_fingerprint = val
    end
    
    def name_identifier_format
      @name_identifier_format
    end
    def name_identifier_format=(val)
      @name_identifier_format = val
    end
  end
end

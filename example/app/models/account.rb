require 'onelogin/saml'

class Account < ActiveRecord::Base
  def Account.get_saml_settings
    # this is just for testing purposes. 
    
    # should retrieve SAML-settings based on subdomain, IP-address, NameID or similar
    settings = Onelogin::Saml::Settings.new
    
    settings.assertion_consumer_service_url   = "http://localhost:3000/sessions/complete"
    settings.issuer                           = "mysaasapp.com" # the name of your application
    settings.idp_sso_target_url               = "https://app.onelogin.com/saml/signon/8216"
    settings.idp_cert_fingerprint             = "90:CC:16:F1:...."
    settings.name_identifier_format           = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    settings
  end
end

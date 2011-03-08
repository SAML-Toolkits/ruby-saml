module Onelogin::Saml
  class Settings
    attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
    attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :name_identifier_format
    attr_accessor :idp_slo_target_url
    attr_accessor :sessionindex, :name_id

    SLO_ELEMENT_PATH = "/EntityDescriptor/IDPSSODescriptor/SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']"
  end
end

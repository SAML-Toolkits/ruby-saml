module Onelogin::Saml
  class Settings
    attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
    attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :idp_cert, :name_identifier_format
	 attr_accessor :authn_context, :idp_metadata

		def is_valid?
			if idp_metadata == nil
				return false
			end
			return true
		end
  end  
end

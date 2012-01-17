module Onelogin::Saml
  class Settings
    attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
    attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :idp_cert, :name_identifier_format
	 attr_accessor :authn_context, :idp_metadata, :idp_metadata_ttl
	 attr_accessor :assertion_consumer_service_binding, :idp_slo_target_url
	 attr_accessor :single_logout_service_url, :single_logout_service_binding
	 alias :entity_id :issuer
	 alias :acs_url :assertion_consumer_service_url
	 alias :acs_binding :assertion_consumer_service_binding
	 alias :slo_url :single_logout_service_url
	 alias :slo_binding :single_logout_service_binding
	 
		def initialize 
			# Set some sane default values on a few options
			self.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
			self.single_logout_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
			# SAML spec snobs seem to think that transient is the default Name ID that 
			# *everyone* should support.  A good enough default that should cover most installations
			self.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
			# Default cache TTL for metdata is 1 day
			self.idp_metadata_ttl = 86400
		end
		def is_valid?
			# Check conditions Older method of defining fingerprint + target URL
			if idp_metadata == nil
				if idp_sso_target_url == nil
					validation_error("idp_sso_target_url is not defined")
				end
				if idp_cert_fingerprint == nil
					validation_error("idp_cert_fingerprint is not defined")
				end
			end
			if acs_url == nil
				validation_error("assertion_consumer_service_url is not defined")
			end
			if issuer == nil
				validation_error("issuer (entity ID) is not defined")
			end
			return true
		end
		
		def validation_error(message)
			raise ValidationError.new(message)
		end
  end  
end

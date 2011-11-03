require "rexml/document"
require "rexml/xpath"
require "net/http"
require "uri"
require "digest/md5"

# Class to return SP metadata based on the settings requested.
# Return this XML in a controller, then give that URL to the the 
# IdP administrator.  The IdP will poll the URL and your settings
# will be updated automatically
module Onelogin::Saml
	include REXML
	class Metadata
		
		attr_accessor :cache
		
		def initialize
			@cache = Cache.new
		end
		def generate(settings)
			meta_doc = REXML::Document.new
			root = meta_doc.add_element "md:EntityDescriptor", { 
					"xmlns:md" => "urn:oasis:names:tc:SAML:2.0:metadata" 
			}
			sp_sso = root.add_element "md:SPSSODescriptor", { 
					"protocolSupportEnumeration" => "urn:oasis:names:tc:SAML:2.0:protocol"
			}
			if settings.issuer != nil
				root.attributes["entityID"] = settings.issuer
			end
			if settings.name_identifier_format != nil
				name_id = sp_sso.add_element "md:NameIDFormat"
				name_id.text = settings.name_identifier_format
			end
			if settings.assertion_consumer_service_url != nil
				sp_sso.add_element "md:AssertionConsumerService", {
						# Add this as a setting to create different bindings?
						"Binding" => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
						"Location" => settings.assertion_consumer_service_url
				}
			end
			meta_doc << REXML::XMLDecl.new
			ret = ""
			# pretty print the XML so IdP administrators can easily see what the SP supports
			meta_doc.write(ret, 1)
			
			Logging.debug "Generated metadata:\n#{ret}"
			
			return ret
			
		end
		# Retrieve the remote IdP metadata from the URL or a cached copy 
		# returns a REXML document of the metadata
		def get_idp_metadata(settings)
			if ! settings.is_valid? 
				return false
			end
			# Look up the metdata in cache first
			#id = Digest::MD5.hexdigest(settings.idp_metdata)
			#lookup = @cache.read(id)
			#if lookup != nil
			#	return REXML::Document.new( lookup )
			#end
			# cache miss
			uri = URI.parse(settings.idp_metadata)
			response = Net::HTTP.get_response(uri)
			#@cache.write(id, response.body)
			return REXML::Document.new( response.body )
		end
	end
end


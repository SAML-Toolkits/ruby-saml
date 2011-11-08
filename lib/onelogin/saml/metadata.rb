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
			# If we're running in Rails, use the RailsCache
			if defined? Rails
				@cache = RailsCache.new
			# otherwise use strictly in memory caching
			else
				@cache = Cache.new
			end
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
						"Binding" => settings.assertion_consumer_service_binding,
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
			return false if settings.nil?
		
			return false if settings.idp_metadata.nil?
		
			# Look up the metdata in cache first
			id = Digest::MD5.hexdigest(settings.idp_metadata)
			lookup = @cache.read(id)
			if lookup != nil
				Logging.debug "IdP metadata cached lookup for #{settings.idp_metadata}"
				doc = REXML::Document.new( lookup )
				extract_certificate(settings, doc )
				return doc
			end
			
			Logging.debug "IdP metadata cache miss on #{settings.idp_metadata}"
			# cache miss
			if File.exists?(settings.idp_metadata)
				fp = File.open( settings.idp_metadata, "r")
				meta_text = fp.read
			else
				uri = URI.parse(settings.idp_metadata)
				response = Net::HTTP.get_response(uri)
				meta_text = response.body
			end
			# Add it to the cache
			@cache.write(id, meta_text, settings.idp_metadata_ttl )
			doc = REXML::Document.new( meta_text )
			extract_certificate(settings, doc)
			return doc
		end
		
		def extract_certificate(settings, meta_doc)
			# pull out the x509 tag
			settings.idp_cert = REXML::XPath.first(meta_doc, 
							"/EntityDescriptor/IDPSSODescriptor" +
						"/KeyDescriptor[@use='signing']" +
						"/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
					).text.gsub(/\n/, "")
		end
	end
end


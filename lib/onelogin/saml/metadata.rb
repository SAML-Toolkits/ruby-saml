require "rexml/document"
require "rexml/xpath"
require "net/http"
require "uri"
require "digest/md5"

# Class to return SP metadata based on the settings requested.
# Return this XML in a controller, then give that URL to the the 
# IdP administrator.  The IdP will poll the URL and your settings
# will be updated automatically
# Also contains functions to pull IdP metadata, and select
# an appropriate ACS URL.
module Onelogin::Saml
	class Metadata
		include REXML
		include Coding
	  # a few symbols for SAML class names
		HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
		HTTP_GET = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		
		attr_accessor :cache
		
		def initialize( settings )
			# If we're running in Rails, use the RailsCache
			if defined? Rails
				@cache = RailsCache.new
			# otherwise use strictly in memory caching
			else
				@cache = Cache.new
			end
			if settings
				@settings = settings
			end
		end
		def generate
			meta_doc = REXML::Document.new
			root = meta_doc.add_element "md:EntityDescriptor", { 
					"xmlns:md" => "urn:oasis:names:tc:SAML:2.0:metadata" 
			}
			sp_sso = root.add_element "md:SPSSODescriptor", { 
					"protocolSupportEnumeration" => "urn:oasis:names:tc:SAML:2.0:protocol"
			}
			if @settings.issuer != nil
				root.attributes["entityID"] = @settings.issuer
			end
			if @settings.name_identifier_format != nil
				name_id = sp_sso.add_element "md:NameIDFormat"
				name_id.text = @settings.name_identifier_format
			end
			if @settings.assertion_consumer_service_url != nil
				sp_sso.add_element "md:AssertionConsumerService", {
						# Add this as a setting to create different bindings?
						"Binding" => @settings.assertion_consumer_service_binding,
						"Location" => @settings.assertion_consumer_service_url
				}
			end
			if @settings.single_logout_service_url != nil
				sp_sso.add_element "md:SingleLogoutService", {
						# Add this as a setting to create different bindings?
						"Binding" => @settings.single_logout_service_binding,
						"Location" => @settings.single_logout_service_url
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
		def get_idp_metadata
		
			return false if @settings.idp_metadata.nil?
		
			# Look up the metdata in cache first
			id = Digest::MD5.hexdigest(@settings.idp_metadata)
			lookup = @cache.read(id)
			if lookup != nil
				Logging.debug "IdP metadata cached lookup for #{@settings.idp_metadata}"
				doc = REXML::Document.new( lookup )
				extract_certificate( doc )
				return doc
			end
			
			Logging.debug "IdP metadata cache miss on #{@settings.idp_metadata}"
			# cache miss
			if File.exists?(@settings.idp_metadata)
				fp = File.open( @settings.idp_metadata, "r")
				meta_text = fp.read
			else
				uri = URI.parse(@settings.idp_metadata)
				response = Net::HTTP.get_response(uri)
				meta_text = response.body
			end
			# Add it to the cache
			@cache.write(id, meta_text, @settings.idp_metadata_ttl )
			doc = REXML::Document.new( meta_text )
			extract_certificate(doc)
			return doc
		end
		
		def extract_certificate(meta_doc)
			# pull out the x509 tag
			@settings.idp_cert = REXML::XPath.first(meta_doc, 
							"/EntityDescriptor/IDPSSODescriptor" +
						"/KeyDescriptor[@use='signing']" +
						"/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
					).text.gsub(/\n/, "")
		end
		
		def create_sso_request(message, extra_parameters = {} )
			build_message( :type => "SAMLRequest", 
					:service => "SingleSignOnService", 
					:message => message, :extra_parameters => extra_parameters)
		end
		def create_sso_response(message, extra_parameters = {} )
			build_message( :type => "SAMLResponse", 
					:service => "SingleSignOnService", 
					:message => message, :extra_parameters => extra_parameters)			
		end
		def create_slo_request(message, extra_parameters = {} )
			build_message( :type => "SAMLRequest", 
					:service => "SingleLogoutService", 
					:message => message, :extra_parameters => extra_parameters)
		end
		def create_slo_response(message, extra_parameters = {} )
			build_message( :type => "SAMLResponse", 
					:service => "SingleLogoutService", 
					:message => message, :extra_parameters => extra_parameters)			
		end

		# Construct a SAML message using information in the IdP metadata.  
		# :type can be either "SAMLRequest" or "SAMLResponse" 
		# :service refers to the Binding method, 
		#    either "SingleLogoutService" or "SingleSignOnService"
		# :message is the SAML message itself (XML)  
		# I've provided easy to use wrapper functions above 
		def build_message( options = {} )
			opt = { :type => nil, :service => nil, :message => nil, :extra_parameters => nil }.merge(options)
			action, url = binding_select( opt[:service] )
			case action 
			when "GET"
				return action, message_get( opt[:type], url, opt[:message], opt[:extra_parameters] )
			when "POST"
				return action, message_post( options[:type], url, opt[:message], opt[:extra_parameters] )
			end
		end
		
		# get the IdP metadata, and select the appropriate SSO binding
		# that we can support.  Currently this is HTTP-Redirect and HTTP-POST
		# but more could be added in the future
		def binding_select(service)
			# first check if we're still using the old hard coded method for 
			# backwards compatability
			if service == "SingleSignOnService" && 
				@settings.idp_metadata == nil && @settings.idp_sso_target_url != nil
					return "GET", @settings.idp_sso_target_url
			end
			if service == "SingleLogoutService" && 
				@settings.idp_metadata == nil	&& @settings.idp_slo_target_url != nil
					return "GET", @settings.idp_slo_target_url
			end
			
			meta_doc = get_idp_metadata
			
			return nil unless meta_doc
			
			# first try POST
			sso_element = REXML::XPath.first(meta_doc,
				"/EntityDescriptor/IDPSSODescriptor/#{service}[@Binding='#{HTTP_POST}']")
			if sso_element 
				@URL = sso_element.attributes["Location"]
				Logging.debug "binding_select: POST to #{@URL}"
				return "POST", @URL
			end
			
			# next try GET
			sso_element = REXML::XPath.first(meta_doc,
				"/EntityDescriptor/IDPSSODescriptor/#{service}[@Binding='#{HTTP_GET}']")
			if sso_element 
				@URL = sso_element.attributes["Location"]
				Logging.debug "binding_select: GET from #{@URL}"
				return "GET", @URL
			end
			# other types we might want to add in the future:  SOAP, Artifact
		end
		# construct the the parameter list on the URL and return
		def message_get( type, url, message, extra_parameters = {} )
			params = Hash.new
			if extra_parameters
				params.merge!(extra_parameters)
			end
			# compress GET requests to try and stay under that 8KB request limit
			params[type] = encode( deflate( message ) )
			
			Logging.debug "#{type}=#{params[type]}"
			
			uri = Addressable::URI.parse(url)
			if uri.query_values == nil
				uri.query_values = params
			else
				# solution to stevenwilkin's parameter merge
				uri.query_values = params.merge(uri.query_values)
			end
			url = uri.to_s
			#url = @URL + "?SAMLRequest=" + @request_params["SAMLRequest"]
			Logging.debug "Sending to URL #{url}"
			return url
		end
		# construct an HTML form (POST) and return the content
		def message_post( type, url, message, extra_parameters = {} )
			params = Hash.new
			if extra_parameters
				params.merge!(extra_parameters)
			end
			
			# POST requests seem to bomb out when they're deflated
			# and they probably don't need to be compressed anyway
			params[type] = encode(message)
			
			#Logging.debug "SAMLRequest=#{@request_params["SAMLRequest"]}"
			# kind of a cheesy method of building an HTML, form since we can't rely on Rails too much,
			# and REXML doesn't work well with quote characters
			str = "<html><body onLoad=\"document.getElementById('form').submit();\">\n"
			str += "<form id='form' name='form' method='POST' action=\"#{@URL}\">\n"
			# we could change this in the future to associate a temp auth session ID
			str += "<input name='RelayState' value='ruby-saml' type='hidden' />\n"
			params.each_pair do |key, value|
				str += "<input name=\"#{key}\" value=\"#{value}\" type='hidden' />\n"
				#str += "<input name=\"#{key}\" value=\"#{CGI.escape(value)}\" type='hidden' />\n"
			end
			str += "</form></body></html>\n"
			
			Logging.debug "Created form:\n#{str}"
			return str
		end
		
	end
end


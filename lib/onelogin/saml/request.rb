
# A few helper functions for assembling a SAMLRequest and 
# sending it to the IdP
module Onelogin::Saml
	include Coding
	module Request
		
	  # a few symbols for SAML class names
		HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
		HTTP_GET = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		# get the IdP metadata, and select the appropriate SSO binding
		# that we can support.  Currently this is HTTP-Redirect and HTTP-POST
		# but more could be added in the future
		def binding_select(service)
			# first check if we're still using the old hard coded method for 
			# backwards compatability
			if @settings.idp_metadata == nil && @settings.idp_sso_target_url != nil
				@URL = @settings.idp_sso_target_url
				return "GET", content_get
			end
			# grab the metadata
			metadata = Metadata::new
			meta_doc = metadata.get_idp_metadata(@settings)
			
			# first try POST
			sso_element = REXML::XPath.first(meta_doc,
				"/EntityDescriptor/IDPSSODescriptor/#{service}[@Binding='#{HTTP_POST}']")
			if sso_element 
				@URL = sso_element.attributes["Location"]
				Logging.debug "binding_select: POST to #{@URL}"
				return "POST", content_post
			end
			
			# next try GET
			sso_element = REXML::XPath.first(meta_doc,
				"/EntityDescriptor/IDPSSODescriptor/#{service}[@Binding='#{HTTP_GET}']")
			if sso_element 
				@URL = sso_element.attributes["Location"]
				Logging.debug "binding_select: GET from #{@URL}"
				return "GET", content_get
			end
			# other types we might want to add in the future:  SOAP, Artifact
		end
		
		# construct the the parameter list on the URL and return
		def content_get
			# compress GET requests to try and stay under that 8KB request limit
			deflated_request  = Zlib::Deflate.deflate(@request, 9)[2..-5]
			# strict_encode64() isn't available?  sub out the newlines
			@request_params["SAMLRequest"] = Base64.encode64(deflated_request).gsub(/\n/, "")
			
			Logging.debug "SAMLRequest=#{@request_params["SAMLRequest"]}"
			uri = Addressable::URI.parse(@URL)
			uri.query_values = @request_params
			url = uri.to_s
			#url = @URL + "?SAMLRequest=" + @request_params["SAMLRequest"]
			Logging.debug "Sending to URL #{url}"
			return url
		end
		# construct an HTML form (POST) and return the content
		def content_post
			# POST requests seem to bomb out when they're deflated
			# and they probably don't need to be compressed anyway
			@request_params["SAMLRequest"] = Base64.encode64(@request).gsub(/\n/, "")
			
			#Logging.debug "SAMLRequest=#{@request_params["SAMLRequest"]}"
			# kind of a cheesy method of building an HTML, form since we can't rely on Rails too much,
			# and REXML doesn't work well with quote characters
			str = "<html><body onLoad=\"document.getElementById('form').submit();\">\n"
			str += "<form id='form' name='form' method='POST' action=\"#{@URL}\">\n"
			# we could change this in the future to associate a temp auth session ID
			str += "<input name='RelayState' value='ruby-saml' type='hidden' />\n"
			@request_params.each_pair do |key, value|
				str += "<input name=\"#{key}\" value=\"#{value}\" type='hidden' />\n"
				#str += "<input name=\"#{key}\" value=\"#{CGI.escape(value)}\" type='hidden' />\n"
			end
			str += "</form></body></html>\n"
			
			Logging.debug "Created form:\n#{str}"
			return str
		end
	end	
end
require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"
require "rubygems"
require "addressable/uri"

module Onelogin::Saml
include REXML
  class Authrequest
	  # a few symbols for SAML class names
	  HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	  HTTP_GET = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	  
	  def initialize(settings)
		  @settings = settings
		  @request_params = Hash.new
	  end
    def create(params = {})
		 	
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
		# Create AuthnRequest root element using REXML 
		request_doc = REXML::Document.new
		request_doc.context[:attribute_quote] = :quote
		root = request_doc.add_element "samlp:AuthnRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
		root.attributes['ID'] = uuid
		root.attributes['IssueInstant'] = time
		root.attributes['Version'] = "2.0"
		
		# Conditionally defined elements based on settings
		if @settings.assertion_consumer_service_url != nil
			root.attributes["AssertionConsumerServiceURL"] = @settings.assertion_consumer_service_url
		end
		if @settings.issuer != nil
			issuer = root.add_element "saml:Issuer", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
			issuer.text = @settings.issuer
		end
		if @settings.name_identifier_format != nil
			root.add_element "samlp:NameIDPolicy", { 
					"xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
					# Might want to make AllowCreate a setting?
					"AllowCreate" => "true",
					"Format" => @settings.name_identifier_format
			}
		end
		
		# BUG fix here -- if an authn_context is defined, add the tags with an "exact"
		# match required for authentication to succeed.  If this is not defined, 
		# the IdP will choose default rules for authentication.  (Shibboleth IdP)
		if @settings.authn_context != nil
			requested_context = root.add_element "samlp:RequestedAuthnContext", { 
				"xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
				"Comparison" => "exact",
			}
			class_ref = requested_context.add_element "saml:AuthnContextClassRef", { 
				"xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
			}			
			class_ref.text = @settings.authn_context
		end
		
		@request = ""
		request_doc.write(@request)
		
		Logging.debug "Created AuthnRequest: #{@request}"
		
      params.each_pair do |key, value|
        #request_params << "&#{key}=#{CGI.escape(value.to_s)}"
			@request_params[key] = value
      end

      #settings.idp_sso_target_url + request_params
		
		# Based on the IdP metadata, select the appropriate binding 
		# and return the action to perform to the controller
		return binding_select
		
    end
	
	 # get the IdP metadata, and select the appropriate SSO binding
	 # that we can support.  Currently this is HTTP-Redirect and HTTP-POST
	 # but more could be added in the future
	def binding_select
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
			"/EntityDescriptor/IDPSSODescriptor/SingleSignOnService[@Binding='#{HTTP_POST}']")
		if sso_element 
			@URL = sso_element.attributes["Location"]
			Logging.debug "binding_select: POST to #{@URL}"
			return "POST", content_post
		end
		
		# next try GET
		sso_element = REXML::XPath.first(meta_doc,
			"/EntityDescriptor/IDPSSODescriptor/SingleSignOnService[@Binding='#{HTTP_GET}']")
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

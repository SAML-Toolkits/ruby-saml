require 'uuid'

module Onelogin::Saml
  class LogoutRequest
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"
	  
    include Coding
	 include Request
    attr_reader :transaction_id
	attr_accessor :settings
	
    def initialize( options = {} )
		opt = {  :request => nil, :settings => nil  }.merge(options)
		@settings = opt[:settings]
		@issue_instant = Onelogin::Saml::LogoutRequest.timestamp
		@request_params = Hash.new
		 # We need to generate a LogoutRequest to send to the IdP
		if opt[:request].nil?
			@transaction_id = UUID.new.generate
		# The IdP sent us a LogoutRequest (IdP initiated SLO)
		else
			begin
				@request = XMLSecurity::SignedDocument.new( decode( opt[:request] ))
				raise if @request.nil?
				raise if @request.root.nil?
				raise if @request.root.namespace != PROTOCOL
			rescue
				@request = XMLSecurity::SignedDocument.new( inflate( decode( opt[:request] ) ) )
			end
			Logging.debug "LogoutRequest is: \n#{@request}"
		end 
    end

    def create( options = {} )
		opt = { :name_id => nil, :session_index => nil, :extra_parameters => nil  }.merge(options)
		return nil unless opt[:name_id]
		
		@request = REXML::Document.new
		@request.context[:attribute_quote] = :quote
		
															
		root = @request.add_element "saml2p:LogoutRequest", { "xmlns:saml2p" => PROTOCOL }
		root.attributes['ID'] = @transaction_id
		root.attributes['IssueInstant'] = @issue_instant
		root.attributes['Version'] = "2.0"

		if @settings && @settings.issuer
			issuer = root.add_element "saml:Issuer", { "xmlns:saml" => ASSERTION	}
			issuer.text = @settings.issuer
		end

		name_id = root.add_element "saml:NameID", { "xmlns:saml" => ASSERTION }
		name_id.text = opt[:name_id]
		# I believe the rest of these are optional
		if @settings && @settings.sp_name_qualifier
			name_id.attributes["NameQualifier"] = @settings.sp_name_qualifier
		end
		if opt[:session_index] 
			session_index = root.add_element "samlp:SessionIndex", { "xmlns:samlp" => PROTOCOL }
			session_index.text = opt[:session_index]
		end
		Logging.debug "Created LogoutRequest: #{@request}"
		meta = Metadata.new(@settings)
		return meta.create_slo_request( to_s, opt[:extra_parameters] )
		#action, content =  binding_select("SingleLogoutService")
		#Logging.debug "action: #{action} content: #{content}"
		#return [action, content]
     end

	# function to return the created request as an XML document
    def to_xml
		text = ""
		@request.write(text, 1)
      return text
    end
	 def to_s
		 @request.to_s
	 end
		# Functions for pulling values out from an IdP initiated LogoutRequest
	def name_id 
		element = REXML::XPath.first(@request, "/p:LogoutRequest/a:NameID", { 
				"p" => PROTOCOL, "a" => ASSERTION } )
		return nil if element.nil?
		# Can't seem to get this to work right...
		#element.context[:compress_whitespace] = ["NameID"]
		#element.context[:compress_whitespace] = :all
		str = element.text.gsub(/^\s+/, "")
		str.gsub!(/\s+$/, "")
		return str
	end
	
	def transaction_id
		return @transaction_id if @transaction_id 
		element = REXML::XPath.first(@request, "/p:LogoutRequest", { 
				"p" => PROTOCOL} )
		return nil if element.nil?
		return element.attributes["ID"]
	end
	def is_valid?
		validate(soft = true)
	end
	
	def validate!
		validate( soft = false )
	end
	def validate( soft = true )
		return false if @request.nil?
      return false if @request.validate(@settings, soft) == false
		
		return true
		
	end
    private 
    
    def self.timestamp
      Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    end
	 
  end
end

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
	
    def initialize( options = { :request => nil, :settings => nil } )
		@settings = options[:settings]
		@issue_instant = Onelogin::Saml::LogoutRequest.timestamp
		@request_params = Hash.new
		 # We need to generate a LogoutRequest to send to the IdP
		if options[:request].nil?
			@transaction_id = UUID.new.generate
		# The IdP sent us a LogoutRequest (IdP initiated SLO)
		else
			@request = XMLSecurity::SignedDocument.new(Base64.decode64( options[:request] ))
			Logging.debug "LogoutRequest is: \n#{@request}"
		end 
    end

    def create(name_id, params={})
      xml(name_id)

		meta = Metadata.new(@settings)
		return meta.create_slo_request( @request, params )
		#action, content =  binding_select("SingleLogoutService")
		#Logging.debug "action: #{action} content: #{content}"
		#return [action, content]
     end

    def xml(name_id)
      @request = <<-EOF
        <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="#{transaction_id}" Version="2.0" IssueInstant="#{@issue_instant}">
                <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{@settings.issuer}</saml:Issuer>
                <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    NameQualifier="#{@settings.sp_name_qualifier}"
                    Format="#{@settings.name_identifier_format}">#{name_id}</saml:NameID>
            <samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">1234</samlp:SessionIndex>
        </samlp:LogoutRequest>
      EOF
		Logging.debug "Created LogoutRequest: #{@request}"
      @request
    end

		# Functions for pulling values out from an IdP initiated LogoutRequest
	def name_id 
		element = REXML::XPath.first(@request, "/p:LogoutRequest/a:NameID", { 
				"p" => PROTOCOL, "a" => ASSERTION } )
		return nil if element.nil?
		return element.text
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

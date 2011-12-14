#encoding: utf-8

require "rexml/document"

module Onelogin
  module Saml
    class LogoutResponse
      include Coding
		include Request
		ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
		PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
		DSIG      = "http://www.w3.org/2000/09/xmldsig#"

      def initialize( options = { :response => nil, :settings => nil })
			# We've recieved a LogoutResponse from the IdP 
			if options[:response]
				begin
					@response = REXML::Document.new(decode( options[:response] ))
					# Check to see if we have a root tag using the "protocol" namespace.
					# If not, it means this is deflated text and we need to raise to 
					# the rescue below
						raise if @response.nil?
						raise if @response.root.nil?
						raise if @response.root.namespace != PROTOCOL
					document
				rescue
					@response = REXML::Document.new( inflate(decode( options[:response] )) )
				end
			end
			# We plan to create() a new LogoutResponse
			if options[:settings]
				@settings = options[:settings]
			end
      end

		# Create a LogoutResponse to to the IdP's LogoutRequest
		#  (For IdP initiated SLO)
		def create( options )
			opt = { :transaction_id => nil, 
				:status => "urn:oasis:names:tc:SAML:2.0:status:Success", 
				:extra_parameters => nil }.merge(options)
			return nil if opt[:transaction_id].nil?
			@response = REXML::Document.new
			@response.context[:attribute_quote] = :quote
			uuid = "_" + UUID.new.generate
			time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
			root = @response.add_element "saml2p:LogoutResponse", { "xmlns:saml2p" => PROTOCOL }
			root.attributes['ID'] = uuid
			root.attributes['IssueInstant'] = time
			root.attributes['Version'] = "2.0"
			root.attributes['InResponseTo'] = opt[:transaction_id]
			if opt[:status]
				status = root.add_element "saml2p:Status"
				status_code = status.add_element "saml2p:StatusCode", {
						"Value" => opt[:status]
				}
			end
			if @settings && @settings.issuer
				issuer = root.add_element "saml:Issuer", {
					"xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
				}
				issuer.text = @settings.issuer
			end
			meta = Metadata.new( @settings )
			saml_text = ""
			@response.write(saml_text, 1)
			Logging.debug "Created LogoutResponse:\n#{saml_text}"
			return meta.create_slo_response( saml_text, opt[:extra_parameters] )
			
			#root.attributes['Destination'] = action
			
		end
      def issuer
			element = REXML::XPath.first(@response, "/p:LogoutResponse/a:Issuer", { 
						"p" => PROTOCOL, "a" => ASSERTION} )
			return nil if element.nil?
			element.text
      end

      def in_response_to
			element = REXML::XPath.first(@response, "/p:LogoutResponse", {
					 "p" => PROTOCOL })
			return nil if element.nil?
        element.attributes["InResponseTo"]
      end

      def success?
			element = REXML::XPath.first(@response, "/p:LogoutResponse/p:Status/p:StatusCode", {
					"p" => PROTOCOL })
			return false if element.nil?
        element.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
        
      end

    protected
      def document
        REXML::Document.new(@response)
      end
    end
  end
end

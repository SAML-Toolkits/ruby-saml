#encoding: utf-8

require "rexml/document"

module Onelogin
  module Saml
    class LogoutResponse
      include Coding
		ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
		PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
		DSIG      = "http://www.w3.org/2000/09/xmldsig#"

      def initialize(response)
        begin
          @response = decode(response)
			 # Check to see if we have a root tag using the "protocol" namespace.
			 # If not, it means this is deflated text and we need to raise to 
			 # the rescue below
				raise if document.nil?
				raise if document.root.nil?
				raise if document.root.namespace != PROTOCOL
          document
        rescue
          @response = inflate(decode(response))
        end
      end

      def issuer
			element = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { 
						"p" => PROTOCOL, "a" => ASSERTION} )
			return nil if element.nil?
			element.text
      end

      def in_response_to
			element = REXML::XPath.first(document, "/p:LogoutResponse", {
					 "p" => PROTOCOL })
			return nil if element.nil?
        element.attributes["InResponseTo"]
      end

      def success?
			element = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", {
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

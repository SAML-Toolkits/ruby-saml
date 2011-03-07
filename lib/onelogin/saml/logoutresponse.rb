#encoding: utf-8

require "rexml/document"

module Onelogin
  module Saml
    class Logoutresponse
      include Codeing

      def initialize(response)
        begin
          @response = decode(response)
          document
        rescue
          @response = inflate(decode(response))
        end
      end

      def issuer
        document.elements["/samlp:LogoutResponse/saml:Issuer"].text
      end

      def in_response_to
        document.elements["/samlp:LogoutResponse"].attributes["InResponseTo"]
      end

    protected
      def document
        REXML::Document.new(@response)
      end
    end
  end
end

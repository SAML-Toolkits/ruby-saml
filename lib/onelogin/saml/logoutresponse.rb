#encoding: utf-8

require "rexml/document"

module Onelogin
  module Saml
    class Logoutresponse
      include Codeing

      def initialize(response)
        @response = decode(response)
      end

      def name_id
        document.elements["/samlp:LogoutRequest/saml:NameID"].text
      end

      def issuer
        document.elements["/samlp:LogoutRequest/saml:Issuer"].text
      end

      def transaction_id
        document.elements["/samlp:LogoutRequest/samlp:SessionIndex"].text
      end

    protected
      def document
        REXML::Document.new(@response)
      end
    end
  end
end

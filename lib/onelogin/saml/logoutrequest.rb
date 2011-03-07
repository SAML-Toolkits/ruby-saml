require 'base64'
require 'uuid'
require 'cgi'

module Onelogin::Saml
  class Logoutrequest
    attr_reader :transaction_id

    def initialize
      @transaction_id = UUID.new.generate
    end

    def create(settings,nameid,params={})
      issue_instant = Onelogin::Saml::Logoutrequest.getTimestamp

      @logger.error("sp_name_qualifier is nil") if !@logger.nil? && settings.sp_name_qualifier.nil?
      @logger.error("idp_name_qualifier is nil") if !@logger.nil? && settings.idp_name_qualifier.nil?

      request = <<-EOF
        <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
            ID="#{transaction_id}" Version="2.0" IssueInstant="#{issue_instant}">
                <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{settings.issuer}</saml:Issuer>
                <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
                    NameQualifier="#{settings.sp_name_qualifier}" 
                    SPNameQualifier="#{settings.idp_name_qualifier}" 
                    Format="#{settings.name_identifier_format}">#{nameid}</saml:NameID>
        </samlp:LogoutRequest>
      EOF

      @logger.debug("Raw SAML request: #{request}") unless @logger.nil?
 
      deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
      base64_request    = Base64.encode64(deflated_request)  
      params["SAMLRequest"] = base64_request
      query_string = params.map {|key, value| "#{key}=#{CGI.escape(value)}"}.join("&")

      settings.idp_slo_target_url + "?#{query_string}"
     end

    private 
    
    def self.getTimestamp
      Time.new().strftime("%Y-%m-%dT%H:%M:%SZ")
    end
  end
end

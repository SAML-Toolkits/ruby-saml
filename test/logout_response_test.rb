require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class LogoutResponseTest < Test::Unit::TestCase
	include Onelogin::Saml::Coding
	ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
	PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
	
  context "LogoutResponse" do
      settings = Onelogin::Saml::Settings.new
		 settings.assertion_consumer_service_url   = "http://sp.example.com/saml/consume"
		 settings.issuer = "http://sp.example.com"
		 settings.assertion_consumer_service_binding   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	  settings.idp_sso_target_url = "http://idp.example.com/sso"
	  settings.idp_slo_target_url = "http://idp.example.com/slo"
    should "Create a LogoutResponse" do
		logout_response = Onelogin::Saml::LogoutResponse.new( :settings => settings)
		
		action, content = logout_response.create( :transaction_id => "1234" )
		#puts "action: #{action} content: #{content}"
		assert action == "GET"
		payload  = CGI.unescape(content.split("=").last)
		#puts "payload: '#{payload}'"
		message = inflate(decode(payload))
		#puts "message: #{message}"
		assert_match /^<saml2p:LogoutResponse/, message
		
		doc = REXML::Document.new(message)
		assert_match /^1234$/, doc.root.attributes["InResponseTo"]
		issuer = REXML::XPath.first(doc, "p:LogoutResponse/a:Issuer", { 
						"p" => PROTOCOL, "a" => ASSERTION} )
		#puts "Issuer: '#{issuer.text}'"
		assert settings.issuer == issuer.text
	 end
	 should "Accept a LogoutResponse" do
		 logout_response = Onelogin::Saml::LogoutResponse.new( 
				:settings => settings, :response => logout_response1 )
		assert logout_response.is_valid?
		assert_match /^1234$/, logout_response.in_response_to
		assert_match /^http:\/\/idp\.example\.com$/, logout_response.issuer
	 end
  end
end

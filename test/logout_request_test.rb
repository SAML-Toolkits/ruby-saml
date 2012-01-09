require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class LogoutRequestTest < Test::Unit::TestCase
	include Onelogin::Saml::Coding
  context "LogoutRequest" do
      settings = Onelogin::Saml::Settings.new
		 settings.assertion_consumer_service_url   = "http://sp.example.com/saml/consume"
		 settings.issuer = "http://sp.example.com"
		 settings.assertion_consumer_service_binding   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		settings.idp_sso_target_url = "http://idp.example.com/sso"
	  settings.idp_slo_target_url = "http://idp.example.com/slo"
	  
    should "Create a LogoutRequest" do
		logout_request = Onelogin::Saml::LogoutRequest.new( :settings => settings )
		assert logout_request.transaction_id != nil
		
		assert logout_request.is_valid? == false
		
		action, content = logout_request.create( :name_id => "bob" )
		#puts "action: #{action} content: #{content}"
		assert action == "GET"
		
		payload  = CGI.unescape(content.split("=").last)
		message = inflate(decode(payload))
		#puts "message: #{message}"
		assert_match /^<saml2p:LogoutRequest/ , message
		
		name_id = REXML::XPath.first( REXML::Document.new(message), "/saml2p:LogoutRequest/saml:NameID")
		#puts "name_id: '#{name_id.text}'"
		name_id = name_id.text
		
		assert name_id == "bob"
	 end
	 should "Accept a LogoutRequest" do
		 logout_request = Onelogin::Saml::LogoutRequest.new( 
				:request => logout_request1, :settings => settings )
		
		 assert logout_request.is_valid?
		 
		 assert_match /^bob$/, logout_request.name_id
	 end
	 
  end
end

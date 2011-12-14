require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class LogoutResponseTest < Test::Unit::TestCase

  context "LogoutResponse" do
    should "Create a LogoutResponse" do
      settings = Onelogin::Saml::Settings.new
		 settings.assertion_consumer_service_url   = "http://sp.example.com/saml/consume"
		 settings.issuer = "http://sp.example.com"
		 settings.assertion_consumer_service_binding   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		logout_response = Onelogin::Saml::LogoutResponse.new
		
		
		
	 end
  end
end

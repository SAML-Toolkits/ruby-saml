require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class LogoutRequestTest < Test::Unit::TestCase

  context "LogoutRequest" do
    should "Create a LogoutRequest" do
      settings = Onelogin::Saml::Settings.new
		 settings.assertion_consumer_service_url   = "http://sp.example.com/saml/consume"
		 settings.issuer = "http://sp.example.com"
		 settings.assertion_consumer_service_binding   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		logout_request = Onelogin::Saml::LogoutRequest.new
		assert logout_request.transaction_id != nil
		
		assert logout_request.is_valid? == false
	 end
	 
  end
end

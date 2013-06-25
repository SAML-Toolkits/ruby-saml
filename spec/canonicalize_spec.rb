require 'ruby-saml'

describe "Canonicalization with JRuby" do

  it 'should validate a signed SamlResponse' do
    settings = Onelogin::Saml::Settings.new

    settings.issuer = 'issuer'
    settings.idp_cert_fingerprint = '6D:E1:4C:98:DB:5F:E8:82:C5:14:60:59:0A:FB:3E:10:60:AE:27:AE'
    settings.name_identifier_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    saml_response = IO.read("#{File.dirname(__FILE__)}/saml_response.xml")

    response = Onelogin::Saml::Response.new(saml_response, options = {:skip_conditions => true})
    response.settings = settings

    response.validate!
  end
end
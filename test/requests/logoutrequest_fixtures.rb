#encoding: utf-8

def default_request_opts
  {
      :uuid => "_28024690-000e-0130-b6d2-38f6b112be8b",
      :issue_instant => Time.now.strftime('%Y-%m-%dT%H:%M:%SZ'),
      :nameid => "testuser@example.com",
      :nameid_format => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      :settings => settings
  }
end

def valid_request(opts = {})
  opts = default_request_opts.merge!(opts)

  "<samlp:LogoutRequest
        xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
        xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
        ID=\"#{random_id}\" Version=\"2.0\"
        IssueInstant=\"#{opts[:issue_instant]}\"
        Destination=\"#{opts[:settings].idp_slo_target_url}\">
      <saml:Issuer>#{opts[:settings].idp_entity_id}</saml:Issuer>
      <saml:NameID Format=\"#{opts[:nameid_format]}\">#{opts[:nameid]}</saml:NameID>
      </samlp:LogoutRequest>"
end

def invalid_xml_request
  "<samlp:SomethingAwful
        xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
        ID=\"#{random_id}\" Version=\"2.0\">
      </samlp:SomethingAwful>"
end

def settings
  @settings ||= OneLogin::RubySaml::Settings.new(
      {
          :assertion_consumer_service_url => "http://app.muda.no/sso/consume",
          :single_logout_service_url => "http://app.muda.no/sso/consume_logout",
          :sp_entity_id => "http://app.muda.no",
          :sp_name_qualifier => "http://sso.muda.no",
          :idp_sso_target_url => "http://sso.muda.no/sso",
          :idp_slo_target_url => "http://sso.muda.no/slo",
          :idp_cert_fingerprint => "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
          :name_identifier_format => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      }
  )
end

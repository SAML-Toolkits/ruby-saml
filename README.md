# Ruby SAML [![Build Status](https://secure.travis-ci.org/onelogin/ruby-saml.png)](http://travis-ci.org/onelogin/ruby-saml)

## Updating from 0.8.x to 0.9
Version `0.9` adds many new features and improvements. It is a recommended update for all Ruby SAML users. For more details, please review [the changelog](changelog.md)

## Updating from 0.7.x to 0.8.x
Version `0.8.x` changes the namespace of the gem from `OneLogin::Saml` to `OneLogin::RubySaml`.  Please update your implementations of the gem accordingly.

## Overview

The Ruby SAML library is for implementing the client side of a SAML authorization, i.e. it provides a means for managing authorization initialization and confirmation requests from identity providers.

SAML authorization is a two step process and you are expected to implement support for both.

We created a demo project for Rails4 that uses the latest version of this library: [ruby-saml-example](https://github.com/onelogin/ruby-saml-example)

## Adding Features, Pull Requests
* Fork the repository
* Make your feature addition or bug fix
* Add tests for your new features. This is important so we don't break any features in a future version unintentionally.
* Ensure all tests pass.
* Do not change rakefile, version, or history.
* Open a pull request, following [this template](https://gist.github.com/Lordnibbler/11002759).

## Getting Started
In order to use the toolkit you will need to install the gem (either manually or using Bundler), and require the library in your Ruby application:

Using `Gemfile`

```ruby
# latest stable
gem 'ruby-saml', '~> 0.9'

# or track master for bleeding-edge
gem 'ruby-saml', :github => 'onelogin/ruby-saml'
```

Using Bundler

```sh
gem install ruby-saml
```

When requiring the gem, you can add the whole toolkit
```ruby
require 'onelogin/ruby-saml'
```

or just the required components individually:

```ruby
require 'onelogin/ruby-saml/authrequest'
```

## The Initialization Phase

This is the first request you will get from the identity provider. It will hit your application at a specific URL (that you've announced as being your SAML initialization point). The response to this initialization, is a redirect back to the identity provider, which can look something like this (ignore the saml_settings method call for now):

```ruby
def init
  request = OneLogin::RubySaml::Authrequest.new
  redirect_to(request.create(saml_settings))
end
```

Once you've redirected back to the identity provider, it will ensure that the user has been authorized and redirect back to your application for final consumption, this is can look something like this (the authorize_success and authorize_failure methods are specific to your application):

```ruby
def consume
  response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
  response.settings = saml_settings

  # We validate the SAML Response and check if the user already exists in the system
  if response.is_valid?
     # authorize_success, log the user
     session[:userid] = response.name_id
     session[:attributes] = response.attributes
  else
    authorize_failure  # This method shows an error message
  end
end
```

In the above there are a few assumptions in place, one being that the response.name_id is an email address. This is all handled with how you specify the settings that are in play via the saml_settings method. That could be implemented along the lines of this:

```ruby
def saml_settings
  settings = OneLogin::RubySaml::Settings.new

  settings.assertion_consumer_service_url = "http://#{request.host}/saml/finalize"
  settings.issuer                         = request.host
  settings.idp_sso_target_url             = "https://app.onelogin.com/saml/metadata/#{OneLoginAppId}"
  settings.idp_entity_id                  = "https://app.onelogin.com/saml/metadata/#{OneLoginAppId}"
  settings.idp_sso_target_url             = "https://app.onelogin.com/trust/saml2/http-post/sso/#{OneLoginAppId}"
  settings.idp_slo_target_url             = "https://app.onelogin.com/trust/saml2/http-redirect/slo/#{OneLoginAppId}"
  settings.idp_cert_fingerprint           = OneLoginAppCertFingerPrint
  settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

  # Optional for most SAML IdPs
  settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

  # Optional bindings (defaults to Redirect for logout POST for acs)
  settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  settings.single_logout_service_url_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

  settings
end
```

What's left at this point, is to wrap it all up in a controller and point the initialization and consumption URLs in OneLogin at that. A full controller example could look like this:

```ruby
# This controller expects you to use the URLs /saml/init and /saml/consume in your OneLogin application.
class SamlController < ApplicationController
  def init
    request = OneLogin::RubySaml::Authrequest.new
    redirect_to(request.create(saml_settings))
  end

  def consume
    response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
    response.settings = saml_settings

    # We validate the SAML Response and check if the user already exists in the system
    if response.is_valid?
       # authorize_success, log the user
       session[:userid] = response.name_id
       session[:attributes] = response.attributes
    else
      authorize_failure  # This method shows an error message
    end
  end

  private

  def saml_settings
    settings = OneLogin::RubySaml::Settings.new

    settings.assertion_consumer_service_url = "http://#{request.host}/saml/consume"
    settings.issuer                         = request.host
    settings.idp_sso_target_url             = "https://app.onelogin.com/saml/signon/#{OneLoginAppId}"
    settings.idp_cert_fingerprint           = OneLoginAppCertFingerPrint
    settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # Optional for most SAML IdPs
    settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # Optional. Describe according to IdP specification (if supported) which attributes the SP desires to receive in SAMLResponse.
    settings.attributes_index = 5
    # Optional. Describe an attribute consuming service for support of additional attributes.
    settings.attribute_consuming_service.configure do
      service_name "Service"
      service_index 5
      add_attribute :name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name"
    end

    settings
  end
end
```
## Metadata Based Configuration

The method above requires a little extra work to manually specify attributes about the IdP.  (And your SP application)  There's an easier method -- use a metadata exchange.  Metadata is just an XML file that defines the capabilities of both the IdP and the SP application.  It also contains the X.509 public
key certificates which add to the trusted relationship.  The IdP administrator can also configure custom settings for an SP based on the metadata.

Using ```idp_metadata_parser.parse_remote``` IdP metadata will be added to the settings withouth further ado.

```ruby
def saml_settings

  idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
  # Returns OneLogin::RubySaml::Settings prepopulated with idp metadata
  settings = idp_metadata_parser.parse_remote("https://example.com/auth/saml2/idp/metadata")

  settings.assertion_consumer_service_url = "http://#{request.host}/saml/consume"
  settings.issuer                         = request.host
  settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  # Optional for most SAML IdPs
  settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

  settings
end
```
The following attributes are set:
  * id_sso_target_url
  * idp_slo_target_url
  * id_cert_fingerpint

If are using saml:AttributeStatement to transfer metadata, like the user name, you can access all the attributes through response.attributes. It contains all the saml:AttributeStatement with its 'Name' as a indifferent key the one/more saml:AttributeValue as value. The value returned depends on the value of the
`single_value_compatibility` (when activate, only one value returned, the first one)

```ruby
response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
response.settings = saml_settings

response.attributes[:username]
```

Imagine this saml:AttributeStatement

```xml
  <saml:AttributeStatement>
    <saml:Attribute Name="uid">
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">demo</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="another_value">
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">value1</saml:AttributeValue>
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">value2</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="role">
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">role1</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="role">
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">role2</saml:AttributeValue>
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">role3</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="attribute_with_nil_value">
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>
    </saml:Attribute>
    <saml:Attribute Name="attribute_with_nils_and_empty_strings">
      <saml:AttributeValue/>
      <saml:AttributeValue>valuePresent</saml:AttributeValue>
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>
      <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="1"/>
    </saml:Attribute>
  </saml:AttributeStatement>
```

```ruby
pp(response.attributes)   # is an OneLogin::RubySaml::Attributes object
# => @attributes=
  {"uid"=>["demo"],
   "another_value"=>["value1", "value2"],
   "role"=>["role1", "role2", "role3"],
   "attribute_with_nil_value"=>[nil],
   "attribute_with_nils_and_empty_strings"=>["", "valuePresent", nil, nil]}>

# Active single_value_compatibility
OneLogin::RubySaml::Attributes.single_value_compatibility = true

pp(response.attributes[:uid])
# => "demo"

pp(response.attributes[:role])
# => "role1"

pp(response.attributes.single(:role))
# => "role1"

pp(response.attributes.multi(:role))
# => ["role1", "role2", "role3"]

pp(response.attributes[:attribute_with_nil_value])
# => nil

pp(response.attributes[:attribute_with_nils_and_empty_strings])
# => ""

pp(response.attributes[:not_exists])
# => nil

pp(response.attributes.single(:not_exists))
# => nil

pp(response.attributes.multi(:not_exists))
# => nil

# Deactive single_value_compatibility
OneLogin::RubySaml::Attributes.single_value_compatibility = false

pp(response.attributes[:uid])
# => ["demo"]

pp(response.attributes[:role])
# => ["role1", "role2", "role3"]

pp(response.attributes.single(:role))
# => "role1"

pp(response.attributes.multi(:role))
# => ["role1", "role2", "role3"]

pp(response.attributes[:attribute_with_nil_value])
# => [nil]

pp(response.attributes[:attribute_with_nils_and_empty_strings])
# => ["", "valuePresent", nil, nil]

pp(response.attributes[:not_exists])
# => nil

pp(response.attributes.single(:not_exists))
# => nil

pp(response.attributes.multi(:not_exists))
# => nil
```

The saml:AuthnContextClassRef of the AuthNRequest can be provided by `settings.authn_context` , possible values are described at [SAMLAuthnCxt]. The comparison method can be set using the parameter `settings.authn_context_comparison` (the possible values are: 'exact', 'better', 'maximum' and 'minimum'), 'exact' is the default value.
If we want to add a saml:AuthnContextDeclRef, define a `settings.authn_context_decl_ref`.


## Signing

The Ruby Toolkit supports 2 different kinds of signature: Embeded and as GET parameter

In order to be able to sign we need first to define the private key and the public cert of the service provider

```ruby
  settings.certificate = "CERTIFICATE TEXT WITH HEADS"
  settings.private_key = "PRIVATE KEY TEXT WITH HEADS"
```

The settings related to sign are stored in the `security` attribute of the settings:

```ruby
  settings.security[:authn_requests_signed]  = true     # Enable or not signature on AuthNRequest
  settings.security[:logout_requests_signed] = true     # Enable or not signature on Logout Request
  settings.security[:logout_responses_signed] = true     # Enable or not signature on Logout Response

  settings.security[:digest_method]    = XMLSecurity::Document::SHA1
  settings.security[:signature_method] = XMLSecurity::Document::SHA1

  settings.security[:embed_sign]        = false                # Embeded signature or HTTP GET parameter Signature
```


## Single Log Out

The Ruby Toolkit supports SP-initiated Single Logout and IdP-Initiated Single Logout.

Here is an example that we could add to our previous controller to generate and send a SAML Logout Request to the IdP

```ruby
# Create a SP initiated SLO
def sp_logout_request
  # LogoutRequest accepts plain browser requests w/o paramters
  settings = saml_settings

  if settings.idp_slo_target_url.nil?
    logger.info "SLO IdP Endpoint not found in settings, executing then a normal logout'"
    delete_session
  else

    # Since we created a new SAML request, save the transaction_id
    # to compare it with the response we get back
    logout_request = OneLogin::RubySaml::Logoutrequest.new()
    session[:transaction_id] = logout_request.uuid
    logger.info "New SP SLO for userid '#{session[:userid]}' transactionid '#{session[:transaction_id]}'"

    if settings.name_identifier_value.nil?
      settings.name_identifier_value = session[:userid]
    end

    relayState =  url_for controller: 'saml', action: 'index'
    redirect_to(logout_request.create(settings, :RelayState => relayState))
  end
end
```

and this method process the SAML Logout Response sent by the IdP as reply of the SAML Logout Request

```ruby
# After sending an SP initiated LogoutRequest to the IdP, we need to accept
# the LogoutResponse, verify it, then actually delete our session.
def process_logout_response
  settings = Account.get_saml_settings

  if session.has_key? :transation_id
    logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], settings, :matches_request_id => session[:transation_id])
  else
    logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], settings)
  end

  logger.info "LogoutResponse is: #{logout_response.to_s}"

  # Validate the SAML Logout Response
  if not logout_response.validate
    logger.error "The SAML Logout Response is invalid"
  else
    # Actually log out this session
    if logout_response.success?
      logger.info "Delete session for '#{session[:userid]}'"
      delete_session
    end
  end
end

# Delete a user's session.
def delete_session
  session[:userid] = nil
  session[:attributes] = nil
end
```

Here is an example that we could add to our previous controller to process a SAML Logout Request from the IdP and reply a SAML Logout Response to the IdP

```ruby
# Method to handle IdP initiated logouts
def idp_logout_request
  settings = Account.get_saml_settings
  logout_request = OneLogin::RubySaml::SloLogoutrequest.new(params[:SAMLRequest])
  if !logout_request.is_valid?
    logger.error "IdP initiated LogoutRequest was not valid!"
    render :inline => logger.error
  end
  logger.info "IdP initiated Logout for #{logout_request.name_id}"

  # Actually log out this session
  delete_session

  # Generate a response to the IdP.
  logout_request_id = logout_request.id
  logout_response = OneLogin::RubySaml::SloLogoutresponse.new.create(settings, logout_request_id, nil, :RelayState => params[:RelayState])
  redirect_to logout_response
end
```

All the mentioned methods could be handled in a unique view:

```ruby
# Trigger SP and IdP initiated Logout requests
def logout
  # If we're given a logout request, handle it in the IdP logout initiated method
  if params[:SAMLRequest]
    return idp_logout_request
  # We've been given a response back from the IdP, process it
  elsif params[:SAMLResponse]
    return process_logout_response
  # Initiate SLO (send Logout Request)
  else
    return sp_logout_request
  end
end
```



## Service Provider Metadata

To form a trusted pair relationship with the IdP, the SP (you) need to provide metadata XML
to the IdP for various good reasons.  (Caching, certificate lookups, relaying party permissions, etc)

The class `OneLogin::RubySaml::Metadata` takes care of this by reading the Settings and returning XML.  All you have to do is add a controller to return the data, then give this URL to the IdP administrator.

The metdata will be polled by the IdP every few minutes, so updating your settings should propagate
to the IdP settings.

```ruby
class SamlController < ApplicationController
  # ... the rest of your controller definitions ...
  def metadata
    settings = Account.get_saml_settings
    meta = OneLogin::RubySaml::Metadata.new
    render :xml => meta.generate(settings), :content_type => "application/samlmetadata+xml"
  end
end
```

## Clock Drift

Server clocks tend to drift naturally. If during validation of the response you get the error "Current time is earlier than NotBefore condition" then this may be due to clock differences between your system and that of the Identity Provider.

First, ensure that both systems synchronize their clocks, using for example the industry standard [Network Time Protocol (NTP)](http://en.wikipedia.org/wiki/Network_Time_Protocol).

Even then you may experience intermittent issues though, because the clock of the Identity Provider may drift slightly ahead of your system clocks. To allow for a small amount of clock drift you can initialize the response passing in an option named `:allowed_clock_drift`. Its value must be given in a number (and/or fraction) of seconds. The value given is added to the current time at which the response is validated before it's tested against the `NotBefore` assertion. For example:

```ruby
response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], :allowed_clock_drift => 1.second)
```

Make sure to keep the value as comfortably small as possible to keep security risks to a minimum.

## Attribute Service

To request attributes from the IdP the SP needs to provide an attribute service within it's metadata and reference the index in the assertion.

```ruby
settings = OneLogin::RubySaml::Settings.new

settings.attributes_index = 5
settings.attribute_consuming_service.configure do
  service_name "Service"
  service_index 5
  add_attribute :name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name"
  add_attribute :name => "Another Attribute", :name_format => "Name Format", :friendly_name => "Friendly Name", :attribute_value => "Attribute Value"
end
```

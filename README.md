# Ruby SAML [![Build Status](https://secure.travis-ci.org/onelogin/ruby-saml.png)](http://travis-ci.org/onelogin/ruby-saml)

## Updating from 0.7.x to 0.8.x
Version `0.8.x` changes the namespace of the gem from `OneLogin::Saml` to `OneLogin::RubySaml`.  Please update your implementations of the gem accordingly.

## Overview

The Ruby SAML library is for implementing the client side of a SAML authorization, i.e. it provides a means for managing authorization initialization and confirmation requests from identity providers.

SAML authorization is a two step process and you are expected to implement support for both.

We created a demo project for Rails4 that uses the latest version of this library: [ruby-saml-example](https://github.com/onelogin/ruby-saml-example)

## Getting Started
In order to use the toolkit you will need to install the gem (either manually or using Bundler), and require the library in your Ruby application:

Using `Gemfile`

```ruby
# latest stable
gem 'ruby-saml', '~> 0.8.1'

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
    settings.attributes_index = 30

    settings
  end
end
```

If are using saml:AttributeStatement to transfer metadata, like the user name, you can access all the attributes through response.attributes. It contains all the saml:AttributeStatement with its 'Name' as a indifferent key the one/more saml:AttributeValue as value. The value returned depends on the value of the
`single_value_compatibility` (when activate, only one value returned, the first one).


```ruby
response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
response.settings = saml_settings

response.attributes[:username]
```

## Single Log Out

Right now the Ruby Toolkit only supports SP-initiated Single Logout (The IdP-Initiated SLO will be supported soon).

Here is an example that we could add to our previous controller to generate and send a SAML Logout Request to the IdP

```ruby

  # Create an SP initiated SLO
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
  def logout_response
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
response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], :allowed_clock_drift => 1)
```

Make sure to keep the value as comfortably small as possible to keep security risks to a minimum.

## Adding Features, Pull Requests

* Fork the repository
* Make your feature addition or bug fix
* Add tests for your new features. This is important so we don't break any features in a future version unintentionally.
* Ensure all tests pass.
* Do not change rakefile, version, or history.
* Open a pull request, following [this template](https://gist.github.com/Lordnibbler/11002759).

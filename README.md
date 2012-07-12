# Ruby SAML [![Build Status](https://secure.travis-ci.org/onelogin/ruby-saml.png)](http://travis-ci.org/onelogin/ruby-saml)

The Ruby SAML library is for implementing the client side of a SAML authorization, i.e. it provides a means for managing authorization initialization and confirmation requests from identity providers.

SAML authorization is a two step process and you are expected to implement support for both.

## The initialization phase

This is the first request you will get from the identity provider. It will hit your application at a specific URL (that you've announced as being your SAML initialization point). The response to this initialization, is a redirect back to the identity provider, which can look something like this (ignore the saml_settings method call for now):

```ruby
    def init
      request = Onelogin::Saml::Authrequest.new
      redirect_to(request.create(saml_settings))
    end
```

Once you've redirected back to the identity provider, it will ensure that the user has been authorized and redirect back to your application for final consumption, this is can look something like this (the authorize_success and authorize_failure methods are specific to your application):

```ruby
    def consume
      response          = Onelogin::Saml::Response.new(params[:SAMLResponse])
      response.settings = saml_settings

      if response.is_valid? && user = current_account.users.find_by_email(response.name_id)
        authorize_success(user)
      else
        authorize_failure(user)
      end
    end
```

In the above there are a few assumptions in place, one being that the response.name_id is an email address. This is all handled with how you specify the settings that are in play via the saml_settings method. That could be implemented along the lines of this:

```ruby
  def saml_settings
    settings = Onelogin::Saml::Settings.new

    settings.assertion_consumer_service_url = "http://#{request.host}/saml/finalize"
    settings.issuer                         = request.host
    settings.idp_sso_target_url             = "https://app.onelogin.com/saml/signon/#{OneLoginAppId}"
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
      request = Onelogin::Saml::Authrequest.new
      redirect_to(request.create(saml_settings))
    end

    def consume
      response          = Onelogin::Saml::Response.new(params[:SAMLResponse])
      response.settings = saml_settings

      if response.is_valid? && user = current_account.users.find_by_email(response.name_id)
        authorize_success(user)
      else
        authorize_failure(user)
      end
    end

    private

    def saml_settings
      settings = Onelogin::Saml::Settings.new

      settings.assertion_consumer_service_url = "http://#{request.host}/saml/consume"
      settings.issuer                         = request.host
      settings.idp_sso_target_url             = "https://app.onelogin.com/saml/signon/#{OneLoginAppId}"
      settings.idp_cert_fingerprint           = OneLoginAppCertFingerPrint
      settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      # Optional for most SAML IdPs
      settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

      settings
    end
  end
```

If are using saml:AttributeStatement to transfare metadata, like the user name, you can access all the attributes through response.attributes. It
contains all the saml:AttributeStatement with its 'Name' as a indifferent key and the one saml:AttributeValue as value.

  response          = Onelogin::Saml::Response.new(params[:SAMLResponse])
  response.settings = saml_settings

  response.attributes[:username]

## Service Provider Metadata

To form a trusted pair relationship with the IdP, the SP (you) need to provide metadata XML
to the IdP for various good reasons.  (Caching, certificate lookups, relying party permissions, etc)

The class Onelogin::Saml::Metdata takes care of this by reading the Settings and returning XML.  All
you have to do is add a controller to return the data, then give this URL to the IdP administrator.
The metdata will be polled by the IdP every few minutes, so updating your settings should propagate
to the IdP settings.

```ruby
  class SamlController < ApplicationController
    # ... the rest of your controller definitions ...
    def metadata
      settings = Account.get_saml_settings
      meta = Onelogin::Saml::Metadata.new
      render :xml => meta.generate(settings)
    end
  end
```

## Note on Patches/Pull Requests

* Fork the project.
* Make your feature addition or bug fix.
* Add tests for it. This is important so I don't break it in a
  future version unintentionally.
* Commit, do not mess with rakefile, version, or history. (if you want to have your own version, that is fine but bump version in a commit by itself I can ignore when I pull)
* Send me a pull request. Bonus points for topic branches.

# Ruby SAML
[![ruby-saml CI](https://github.com/SAML-Toolkits/ruby-saml/actions/workflows/test.yml/badge.svg)](https://github.com/SAML-Toolkits/ruby-saml/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/SAML-Toolkits/ruby-saml/badge.svg?branch=master)](https://coveralls.io/github/SAML-Toolkits/ruby-saml?branch=master)
[![Rubygem Version](https://badge.fury.io/rb/ruby-saml.svg)](https://badge.fury.io/rb/ruby-saml)
[![GitHub version](https://badge.fury.io/gh/SAML-Toolkits%2Fruby-saml.svg)](https://badge.fury.io/gh/SAML-Toolkits%2Fruby-saml) ![GitHub](https://img.shields.io/github/license/SAML-Toolkits/ruby-saml) ![Gem](https://img.shields.io/gem/dtv/ruby-saml?label=gem%20downloads%20latest) ![Gem](https://img.shields.io/gem/dt/ruby-saml?label=gem%20total%20downloads)

Ruby SAML minor versions may introduce breaking changes. Please read
[UPGRADING.md](UPGRADING.md) for guidance on upgrading to new Ruby SAML versions.

## Vulnerability Notice

Please note the following **critical vulnerabilities**:

- CVE-2025-54572 (DOS attack vector) affects version ruby-saml < 1.18.1
- CVE-2024-45409, CVE-2025-25291, CVE-2025-25292, CVE-2025-25293 (SAML authentication bypass) affects ruby-saml < 1.18.0

**Please upgrade to a fixed version (2.0.0 or 1.18.1) as soon as possible.**

## Sponsors

Thanks to the following sponsors for securing the open source ecosystem:

#### [<img class="circle" src="https://avatars.githubusercontent.com/u/34724717" width="26" height="26" alt="@serpapi">](https://serpapi.com) [<sup>SerpApi</sup>](https://github.com/serpapi)
<sup>*A real-time API to access Google search results. It handle proxies, solve captchas, and parse all rich structured data for you*</sup>

#### [<img class="circle" src="https://avatars.githubusercontent.com/u/9919" width="26" height="26" alt="@github">](https://github.com/) [<sup>Github</sup>](https://github.com/github)
<sup>*The complete developer platform to build, scale, and deliver secure software.*</sup>

#### [<img alt="84codes" src="https://avatars.githubusercontent.com/u/5353257" width="26" height="26">](https://www.84codes.com) [<sup>84codes</sup>](https://github.com/84codes)
<sup>*Simplifying Message Queuing and Streaming. Leave server management to the experts, so you can focus on building great applications.*</sup>

#### [<img alt="TableCheck" class="avatar" src="https://avatars.githubusercontent.com/u/36186781" width="26" height="26">](https://www.tablecheck.com/en/join) [<sup>TableCheck</sup>](https://www.tablecheck.com/en/join)
<sup>*Global restaurant reservation and hospitality management platform that delivers extraordinary guest experiences.*</sup>

## Overview

The Ruby SAML library is used by Service Providers (SPs) to implement SAML authentication.
It enables SPs to create SAML AuthnRequests (authentication requests) and validate SAML
Response assertions from Identity Providers (IdPs).

**Important:** This libary does not support the IdP-side of SAML authentication,
such as creating SAML Response messages to assert a user's identity.

A Rails 4 reference implementation is available at the
[Ruby SAML Demo Project](https://github.com/saml-toolkits/ruby-saml-example).

### Vulnerability Reporting

If you believe you have discovered a security vulnerability in this gem, please report
it by email to the maintainer: sixto.martin.garcia+security@gmail.com

### Security Considerations

- **Validation of the IdP Metadata URL:** When loading IdP Metadata from a URLs,
  Ruby SAML requires you (the developer/administrator) to ensure the supplied URL is correct
  and from a trusted source. Ruby SAML does not perform any validation that the URL
  you entered is correct and/or safe.
- **False-Positive Security Warnings:** Some tools may incorrectly report Ruby SAML as a
  potential security vulnerability, due to its dependency on Nokogiri. Such warnings can
  be ignored; Ruby SAML uses Nokogiri in a safe way, by always disabling its DTDLOAD option
  and enabling its NONET option.
- **Prevent Replay attacks:** A replay attack is when an attacker intercepts a valid SAML assertion and "replays" it at a later time to gain unauthorized access. The `ruby-saml` library provides the tools to prevent this, but **you, the developer, must implement the core logic**, see an specific section later in the README.

### Supported Ruby Versions

The following Ruby versions are covered by CI testing:

* Ruby (MRI) 3.0 to 3.4
* JRuby 9.4 to 10.0
* TruffleRuby (latest)

Older Ruby versions are supported on the 1.x release of Ruby SAML.

## Getting Started

You may install Ruby SAML from the command line:

```sh
gem install ruby-saml
```

or in your project `Gemfile`:

```ruby
gem 'ruby-saml', '~> 2.0.0'
```

### Configuring Logging

Ruby SAML provides verbose logs which are useful to troubleshooting SAML integration issues.
By default, log messages are emitted to Rails' logger if using Rails, otherwise to `STDOUT`.
You may manually set your own logger as follows:

```ruby
RubySaml::Logging.logger = Logger.new('/var/log/ruby-saml.log')
```

# Implementation Guide

## The Initialization Phase

This is the first request you will get from the identity provider. It will hit your application
at a specific URL that you've announced as your SAML initialization point. The response to
this initialization is a redirect back to the identity provider, which can look something
like this (ignore the saml_settings method call for now):

```ruby
def init
  request = RubySaml::Authrequest.new
  redirect_to(request.create(saml_settings))
end
```

If you (the SP) know which specific user should be authenticated by the IdP,
then can provide that info as follows:

```ruby
def init
  request = RubySaml::Authrequest.new
  saml_settings.name_identifier_value_requested = "testuser@example.com"
  saml_settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  redirect_to(request.create(saml_settings))
end
```

Once you've redirected back to the identity provider, it will ensure that the user has been
authenticated and redirect back to your application for final consumption.
This can look something like this (the `authn_success` and `authn_failure`
methods are specific to your application):

```ruby
def consume
  response = RubySaml::Response.new(params[:SAMLResponse], settings: saml_settings)

  # We validate the SAML Response and check if the user already exists in the system
  if response.is_valid?
    authn_success(response) # This is your method to log the user, etc.
    session[:userid] = response.nameid
    session[:attributes] = response.attributes
  else
    authn_failure(response) # This is your method to log the failure and show an error message, etc.
    # The list of errors is available in response.errors array
  end
end
```

In the above there are a few assumptions, one being that `response.nameid` is an email address.
This is all handled with how you specify the settings that are in play via the `saml_settings` method.
That could be implemented along the lines of this:

```ruby
response = RubySaml::Response.new(params[:SAMLResponse])
response.settings = saml_settings
```

If the assertion of the SAMLResponse is not encrypted, you can initialize the Response
without the `:settings` parameter and set it later. If the SAMLResponse contains an encrypted
assertion, you need to provide the settings in the initialize method in order to obtain the
decrypted assertion, using the service provider private key in order to decrypt.
If you don't know what expect, always use the former (set the settings on initialize).

```ruby
def saml_settings
  settings = RubySaml::Settings.new

  settings.assertion_consumer_service_url = "https://www.my-domain.com/saml/consume"
  settings.sp_entity_id                   = "https://www.my-domain.com/saml/metadata"
  settings.idp_entity_id                  = "https://www.your-idp.com/saml/metadata/#{IdpAppId}"
  settings.idp_sso_service_url            = "https://www.your-idp.com/saml/#{IdpAppId}"
  settings.idp_sso_service_binding        = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" # or :post, :redirect
  settings.idp_slo_service_url            = "https://www.your-idp.com/saml/slo/#{IdpAppId}"
  settings.idp_slo_service_binding        = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" # or :post, :redirect
  settings.idp_cert_fingerprint           = IdpAppCertFingerPrint
  settings.idp_cert_fingerprint_algorithm = "http://www.w3.org/2000/09/xmldsig#sha256"
  settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

  # Optional for most SAML IdPs
  settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
  # or as an array
  settings.authn_context = [
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
  ]

  # Optional bindings (defaults to Redirect for logout POST for ACS)
  settings.single_logout_service_binding      = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" # or :post, :redirect
  settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" # or :post, :redirect

  settings
end
```

The use of settings.issuer is deprecated in favor of settings.sp_entity_id since version 1.11.0

Some assertion validations can be skipped by passing parameters to `RubySaml::Response.new()`.
For example, you can skip the `AuthnStatement`, `Conditions`, `Recipient`, or the `SubjectConfirmation`
validations by initializing the response with different options:

```ruby
response = RubySaml::Response.new(params[:SAMLResponse], { skip_authnstatement: true }) # skips AuthnStatement
response = RubySaml::Response.new(params[:SAMLResponse], { skip_conditions: true }) # skips conditions
response = RubySaml::Response.new(params[:SAMLResponse], { skip_subject_confirmation: true }) # skips subject confirmation
response = RubySaml::Response.new(params[:SAMLResponse], { skip_recipient_check: true }) # doesn't skip subject confirmation, but skips the recipient check which is a sub check of the subject_confirmation check
response = RubySaml::Response.new(params[:SAMLResponse], { skip_audience: true }) # skips audience check
```

All that's left is to wrap everything in a controller and reference it in the initialization and
consumption URLs. A full controller example could look like this:

```ruby
# This controller expects you to use the URLs /saml/init and /saml/consume in your application.
class SamlController < ApplicationController
  def init
    request = RubySaml::Authrequest.new
    redirect_to(request.create(saml_settings))
  end

  def consume
    response          = RubySaml::Response.new(params[:SAMLResponse])
    response.settings = saml_settings

    # We validate the SAML Response and check if the user already exists in the system
    if response.is_valid?
      authn_success(response) # This is your method to log the user, etc.
      session[:userid] = response.nameid
      session[:attributes] = response.attributes
    else
      authn_failure(response) # This is your method to log the failure and show an error message, etc.
      # The list of errors is available in response.errors array
    end
  end

  private

  def saml_settings
    settings = RubySaml::Settings.new

    settings.assertion_consumer_service_url = "https://www.my-sp-domain.com/saml/consume"
    settings.sp_entity_id                   = "https://www.my-sp-domain.com/saml/metadata"
    settings.idp_sso_service_url            = "https://www.your-idp.com/saml/#{IdpAppId}"
    settings.idp_cert_fingerprint           = IdpAppCertFingerPrint
    settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # Optional for most SAML IdPs
    settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # Optional. Describe according to IdP specification (if supported) which attributes the SP desires to receive in SAMLResponse.
    settings.attributes_index = 5
    # Optional. Describe an attribute consuming service for support of additional attributes.
    settings.attribute_consuming_service.configure do
      service_name "Service"
      service_index 5
      add_attribute name: "Name", name_format: "Name Format", friendly_name: "Friendly Name"
    end

    settings
  end
end
```

## Signature Validation

Ruby SAML allows different ways to validate the signature of the SAML Response:
- You may provide the IdP X.509 public certificate at the `idp_cert` setting.
- (Deprecated) You may provide the IdP X.509 public certificate in fingerprint format using the
  `idp_cert_fingerprint` and `idp_cert_fingerprint_algorithm` parameters.

In addition, you may pass the option `:relax_signature_validation` to `SloLogoutrequest` and
`Logoutresponse` if you want to skip signature validation on logout.

The `idp_cert_fingerprint` option is deprecated for the following reasons. It will be
removed in Ruby SAML version 2.1.0.
1. It only works with HTTP-POST binding, not HTTP-Redirect, since the full certificate
   is not sent in the Redirect URL parameters.
2. It is theoretically susceptible to collision attacks, by which a malicious
   actor could impersonate the IdP. (However, as of January 2025, such attacks have not
   been publicly demonstrated for SHA-256.)
3. It has been removed already from several other SAML libraries in other languages.

## Handling Multiple IdP Certificates

If the IdP metadata XML includes multiple certificates, you may specify the `idp_cert_multi`
parameter. When used, the `idp_cert` and `idp_cert_fingerprint` parameters are ignored.
This is useful in the following scenarios:

* The IdP uses different certificates for signing versus encryption.
* The IdP is undergoing a key rollover and is publishing the old and new certificates in parallel.

The `idp_cert_multi` must be a `Hash` as follows. The `:signing` and `:encryption` arrays below,
add the IdP X.509 public certificates which were published in the IdP metadata.

```ruby
{
  signing: [],
  encryption: []
}
```

## Metadata Based Configuration

The method above requires a little extra work to manually specify attributes about both the IdP and your SP application.
There's an easier method: use a metadata exchange. Metadata is an XML file that defines the capabilities of both the IdP
and the SP application. It also contains the X.509 public key certificates which add to the trusted relationship.
The IdP administrator can also configure custom settings for an SP based on the metadata.

Using `IdpMetadataParser#parse_remote`, the IdP metadata will be added to the settings.

```ruby
def saml_settings

  idp_metadata_parser = RubySaml::IdpMetadataParser.new
  # Returns RubySaml::Settings pre-populated with IdP metadata
  settings = idp_metadata_parser.parse_remote("https://www.your-idp.com/saml/metadata/#{IdpAppId}.xml")

  settings.assertion_consumer_service_url = "https://www.my-sp-domain.com/saml/consume"
  settings.sp_entity_id                   = "https://www.my-sp-domain.com/saml/metadata"
  settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  # Optional for most SAML IdPs
  settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

  settings
end
```

The following attributes are set:
  * idp_entity_id
  * name_identifier_format
  * idp_sso_service_url
  * idp_slo_service_url
  * idp_attribute_names
  * idp_cert
  * idp_cert_fingerprint
  * idp_cert_multi

### Retrieve one Entity Descriptor when many exist in Metadata

If the Metadata contains several entities, the relevant Entity
Descriptor can be specified when retrieving the settings from the
IdpMetadataParser by its Entity Id value:

```ruby
  validate_cert = true
  settings = idp_metadata_parser.parse_remote(
               "https://example.com/auth/saml2/idp/metadata",
               validate_cert,
               entity_id: "http//example.com/target/entity"
             )
```

### Retrieve one Entity Descriptor with an specific binding and nameid format when several are available

If the Metadata contains several bindings and nameids, the relevant ones
also can be specified when retrieving the settings from the IdpMetadataParser
by the values of binding and nameid:

```ruby
  validate_cert = true
  options = {
    entity_id: "http//example.com/target/entity",
    name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    sso_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    slo_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  }
  settings = idp_metadata_parser.parse_remote(
               "https://example.com/auth/saml2/idp/metadata",
               validate_cert,
               options
             )
```

### Parsing Metadata into an Hash

The `RubySaml::IdpMetadataParser` also provides the methods `#parse_to_hash` and `#parse_remote_to_hash`.
Those return an Hash instead of a `Settings` object, which may be useful for configuring
[omniauth-saml](https://github.com/omniauth/omniauth-saml), for instance.

### Validating Signature of Metadata and retrieve settings

Right now there is no method at ruby_saml to validate the signature of the metadata that is going to be parsed, but it can be done as follows:
* Download the XML.
* Validate the Signature, providing the cert.
* Provide the XML to the parse method if the signature was validated

```ruby
require "ruby_saml/xml"
require "ruby_saml/utils"
require "ruby_saml/idp_metadata_parser"

url = "<url_to_the_metadata>"
idp_metadata_parser = RubySaml::IdpMetadataParser.new

uri = URI.parse(url)
raise ArgumentError.new("url must begin with http or https") unless /^https?/ =~ uri.scheme
http = Net::HTTP.new(uri.host, uri.port)
if uri.scheme == "https"
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
end

get = Net::HTTP::Get.new(uri.request_uri)
get.basic_auth uri.user, uri.password if uri.user
response = http.request(get)
xml = response.body
errors = []
doc = RubySaml::XML::SignedDocument.new(xml, errors)
cert_str = "<include_cert_here>"
cert = RubySaml::Utils.format_cert("cert_str")
metadata_sign_cert = OpenSSL::X509::Certificate.new(cert)
valid = doc.validate_document_with_cert(metadata_sign_cert, true)
if valid
  settings = idp_metadata_parser.parse(
    xml,
    entity_id: "<entity_id_of_the_entity_to_be_retrieved>"
  )
else
  print "Metadata Signature failed to be verified with the cert provided"
end
```

## Retrieving Attributes

If you are using `saml:AttributeStatement` to transfer data like the username, you can access all the attributes through `response.attributes`. It contains all the `saml:AttributeStatement`s with its 'Name' as an indifferent key and one or more `saml:AttributeValue`s as values. The value returned depends on the value of the
`single_value_compatibility` (when activated, only the first value is returned)

```ruby
response = RubySaml::Response.new(params[:SAMLResponse])
response.settings = saml_settings

response.attributes[:username]
```

Imagine this `saml:AttributeStatement`

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
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
      <saml:AttributeValue>usersName</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
```

```ruby
pp(response.attributes)   # is an RubySaml::Attributes object
# => @attributes=
#  {"uid"=>["demo"],
#   "another_value"=>["value1", "value2"],
#   "role"=>["role1", "role2", "role3"],
#   "attribute_with_nil_value"=>[nil],
#   "attribute_with_nils_and_empty_strings"=>["", "valuePresent", nil, nil]
#   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"=>["usersName"]}>

# Active single_value_compatibility
RubySaml::Attributes.single_value_compatibility = true

pp(response.attributes[:uid])
# => "demo"

pp(response.attributes[:role])
# => "role1"

pp(response.attributes.single(:role))
# => "role1"

pp(response.attributes.multi(:role))
# => ["role1", "role2", "role3"]

pp(response.attributes.fetch(:role))
# => "role1"

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

pp(response.attributes.fetch(/givenname/))
# => "usersName"

# Deprecated single_value_compatibility
RubySaml::Attributes.single_value_compatibility = false

pp(response.attributes[:uid])
# => ["demo"]

pp(response.attributes[:role])
# => ["role1", "role2", "role3"]

pp(response.attributes.single(:role))
# => "role1"

pp(response.attributes.multi(:role))
# => ["role1", "role2", "role3"]

pp(response.attributes.fetch(:role))
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

pp(response.attributes.fetch(/givenname/))
# => ["usersName"]
```

The `saml:AuthnContextClassRef` of the AuthNRequest can be provided by `settings.authn_context`; possible values are described at [SAMLAuthnCxt]. The comparison method can be set using `settings.authn_context_comparison` parameter. Possible values include: 'exact', 'better', 'maximum' and 'minimum' (default value is 'exact').
To add a `saml:AuthnContextDeclRef`, define `settings.authn_context_decl_ref`.

In a SP-initiated flow, the SP can indicate to the IdP the subject that should be authenticated. This is done by defining the `settings.name_identifier_value_requested` before
building the authrequest object.

## SP Metadata

To form a trusted pair relationship with the IdP, the SP (you) need to provide metadata XML
to the IdP for various good reasons. (Caching, certificate lookups, relaying party permissions, etc)

The class `RubySaml::Metadata` takes care of this by reading the Settings and returning XML.  All you have to do is add a controller to return the data, then give this URL to the IdP administrator.

The metadata will be polled by the IdP every few minutes, so updating your settings should propagate
to the IdP settings.

```ruby
class SamlController < ApplicationController
  # ... the rest of your controller definitions ...
  def metadata
    settings = Account.get_saml_settings
    meta = RubySaml::Metadata.new
    render xml: meta.generate(settings), content_type: "application/samlmetadata+xml"
  end
end
```

You can add `ValidUntil` and `CacheDuration` to the SP Metadata XML using instead:

```ruby
# Valid until => 2 days from now
# Cache duration = 604800s = 1 week
valid_until = Time.now + 172800
cache_duration = 604800
meta.generate(settings, false, valid_until, cache_duration)
```

## Signing and Decryption

Ruby SAML supports the following functionality:

1. Signing your SP Metadata XML
2. Signing your SP SAML messages
3. Decrypting IdP Assertion messages upon receipt (EncryptedAssertion)
4. Verifying signatures on SAML messages and IdP Assertions

In order to use functions 1-3 above, you must first define your SP public certificate and private key:

```ruby
settings.certificate = "CERTIFICATE TEXT WITH BEGIN/END HEADER AND FOOTER"
settings.private_key = "PRIVATE KEY TEXT WITH BEGIN/END HEADER AND FOOTER"
```

Note that the same certificate (and its associated private key) are used to perform
all decryption and signing-related functions (1-4) above. Ruby SAML does not currently allow
to specify different certificates for each function.

You may also globally set the SP signature and digest method, to be used in SP signing (functions 1 and 2 above):

```ruby
settings.security[:digest_method]    = RubySaml::XML::SHA1
settings.security[:signature_method] = RubySaml::XML::RSA_SHA1
```

### Signing SP Metadata

You may add a `<ds:Signature>` digital signature element to your SP Metadata XML using the following setting:

```ruby
settings.certificate = "CERTIFICATE TEXT WITH BEGIN/END HEADER AND FOOTER"
settings.private_key = "PRIVATE KEY TEXT WITH BEGIN/END HEADER AND FOOTER"

settings.security[:metadata_signed] = true # Enable signature on Metadata
```

### Signing SP SAML Messages

Ruby SAML supports SAML request signing. You (the SP) will sign the
request/responses with your private key. The IdP will then validate the signature
of the received request/responses with the SP's public X.509 cert.

To enable, please first set your certificate and private key. This will add `<md:KeyDescriptor use="signing">`
to your SP Metadata XML, to be read by the IdP.

```ruby
settings.certificate = "CERTIFICATE TEXT WITH BEGIN/END HEADER AND FOOTER"
settings.private_key = "PRIVATE KEY TEXT WITH BEGIN/END HEADER AND FOOTER"
```

Next, you may specify the specific SP SAML messages you would like to sign:

```ruby
settings.security[:authn_requests_signed]   = true  # Enable signature on AuthNRequest
settings.security[:logout_requests_signed]  = true  # Enable signature on Logout Request
settings.security[:logout_responses_signed] = true  # Enable signature on Logout Response
```

Signatures will be handled automatically for both `HTTP-POST` and `HTTP-Redirect` Binding.
Note that the RelayState parameter is used when creating the Signature on the `HTTP-Redirect` Binding.
Remember to provide it to the Signature builder if you are sending a `GET RelayState` parameter or the
signature validation process will fail at the IdP.

### Decrypting IdP SAML Assertions

Ruby SAML supports EncryptedAssertion. The IdP will encrypt the Assertion with the
public cert of the SP. The SP will decrypt the EncryptedAssertion with its private key.

You may enable EncryptedAssertion as follows. This will add `<md:KeyDescriptor use="encryption">` to your
SP Metadata XML, to be read by the IdP.

```ruby
settings.certificate = "CERTIFICATE TEXT WITH BEGIN/END HEADER AND FOOTER"
settings.private_key = "PRIVATE KEY TEXT WITH BEGIN/END HEADER AND FOOTER"

settings.security[:want_assertions_encrypted] = true # Invalidate SAML messages without an EncryptedAssertion
```

### Verifying Signature on IdP Assertions

You may require the IdP to sign its SAML Assertions using the following setting.
This will add `<md:SPSSODescriptor WantAssertionsSigned="true">` to your SP Metadata XML.
The signature will be checked against the `<md:KeyDescriptor use="signing">` element
present in the IdP's metadata.

```ruby
settings.security[:want_assertions_signed]  = true  # Require the IdP to sign its SAML Assertions
```

### Certificate and Signature Validation

You may require SP and IdP certificates to be non-expired using the following settings:

```ruby
settings.security[:check_idp_cert_expiration] = true  # Raise error if IdP X.509 cert is expired
settings.security[:check_sp_cert_expiration] = true   # Raise error SP X.509 cert is expired
```

By default, Ruby SAML will raise a `RubySaml::ValidationError` if a signature or certificate
validation fails. You may disable such exceptions using the `settings.security[:soft]` parameter.

```ruby
settings.security[:soft] = true  # Do not raise error on failed signature/certificate validations
```

### Advanced SP Certificate Usage & Key Rollover

Ruby SAML provides the `settings.sp_cert_multi` parameter to enable the following
advanced usage scenarios:
- Rotating SP certificates and private keys without disruption of service.
- Specifying separate SP certificates for signing and encryption.

The `sp_cert_multi` parameter replaces `certificate` and `private_key`
(you may not specify both parameters at the same time.) `sp_cert_multi` has the following shape:

```ruby
settings.sp_cert_multi = {
  signing: [
    { certificate: cert1, private_key: private_key1 },
    { certificate: cert2, private_key: private_key2 }
  ],
  encryption: [
    { certificate: cert1, private_key: private_key1 },
    { certificate: cert3, private_key: private_key1 }
  ],
}
```

Certificate rotation is achieved by inserting new certificates at the bottom of each list,
and then removing the old certificates from the top of the list once your IdPs have migrated.
A common practice is for apps to publish the current SP metadata at a URL endpoint and have
the IdP regularly poll for updates.

Note the following:
- You may re-use the same certificate and/or private key in multiple places, including for both signing and encryption.
- The IdP should attempt to verify signatures with *all* `:signing` certificates,
  and permit if *any one* succeeds. When signing, Ruby SAML will use the first SP certificate
  in the `sp_cert_multi[:signing]` array. This will be the first active/non-expired certificate
  in the array if `settings.security[:check_sp_cert_expiration]` is true.
- The IdP may encrypt with any of the SP certificates in the `sp_cert_multi[:encryption]`
  array. When decrypting, Ruby SAML attempt to decrypt with each SP private key in
  `sp_cert_multi[:encryption]` until the decryption is successful. This will skip private
  keys for inactive/expired certificates if `:check_sp_cert_expiration` is true.
- If `:check_sp_cert_expiration` is true, the generated SP metadata XML will not include
  inactive/expired certificates. This avoids validation errors when the IdP reads the SP
  metadata.

### Key Algorithm Support

Ruby SAML supports RSA, DSA, and ECDSA keys for both SP and IdP certificates.
JRuby cannot support ECDSA due to a [known issue](https://github.com/jruby/jruby-openssl/issues/257).

### Audience Validation

A service provider should only consider a SAML response valid if the IdP includes an <AudienceRestriction>
element containing an <Audience> element that uniquely identifies the service provider. Unless you specify
the `skip_audience` option, Ruby SAML will validate that each SAML response includes an <Audience> element
whose contents matches `settings.sp_entity_id`.

By default, Ruby SAML considers an <AudienceRestriction> element containing only empty <Audience> elements
to be valid. That means an otherwise valid SAML response with a condition like this would be valid:

```xml
<AudienceRestriction>
  <Audience />
</AudienceRestriction>
```

You may enforce that an <AudienceRestriction> element containing only empty <Audience> elements
is invalid using the `settings.security[:strict_audience_validation]` parameter.

```ruby
settings.security[:strict_audience_validation] = true
```

### Single Log Out

Ruby SAML supports SP-initiated Single Logout and IdP-Initiated Single Logout.

Here is an example that we could add to our previous controller to generate and send a SAML Logout Request to the IdP:

```ruby
# Create a SP initiated SLO
def sp_logout_request
  # LogoutRequest accepts plain browser requests w/o paramters
  settings = saml_settings

  if settings.idp_slo_service_url.nil?
    logger.info "SLO IdP Endpoint not found in settings, then executing a normal logout'"
    delete_session
  else

    logout_request = RubySaml::Logoutrequest.new
    logger.info "New SP SLO for userid '#{session[:userid]}' transactionid '#{logout_request.uuid}'"

    if settings.name_identifier_value.nil?
      settings.name_identifier_value = session[:userid]
    end

    # Ensure user is logged out before redirect to IdP, in case anything goes wrong during single logout process (as recommended by saml2int [SDP-SP34])
    logged_user = session[:userid]
    logger.info "Delete session for '#{session[:userid]}'"
    delete_session

    # Save the transaction_id to compare it with the response we get back
    session[:transaction_id] = logout_request.uuid
    session[:logged_out_user] = logged_user

    relayState = url_for(controller: 'saml', action: 'index')
    redirect_to(logout_request.create(settings, 'RelayState' => relayState))
  end
end
```

This method processes the SAML Logout Response sent by the IdP as the reply of the SAML Logout Request:

```ruby
# After sending an SP initiated LogoutRequest to the IdP, we need to accept
# the LogoutResponse, verify it, then actually delete our session.
def process_logout_response
  settings = Account.get_saml_settings

  if session.has_key? :transaction_id
    logout_response = RubySaml::Logoutresponse.new(params[:SAMLResponse], settings, matches_request_id: session[:transaction_id])
  else
    logout_response = RubySaml::Logoutresponse.new(params[:SAMLResponse], settings)
  end

  logger.info "LogoutResponse is: #{logout_response.to_s}"

  # Validate the SAML Logout Response
  if not logout_response.validate
    logger.error "The SAML Logout Response is invalid"
  else
    # Actually log out this session
    logger.info "SLO completed for '#{session[:logged_out_user]}'"
    delete_session
  end
end

# Delete a user's session.
def delete_session
  session[:userid] = nil
  session[:attributes] = nil
  session[:transaction_id] = nil
  session[:logged_out_user] = nil
end
```

Here is an example that we could add to our previous controller to process a SAML Logout Request from the IdP and reply with a SAML Logout Response to the IdP:

```ruby
# Method to handle IdP initiated logouts
def idp_logout_request
  settings = Account.get_saml_settings
  # ADFS URL-Encodes SAML data as lowercase, and the toolkit by default uses
  # uppercase. Turn it True for ADFS compatibility on signature verification
  settings.security[:lowercase_url_encoding] = true

  logout_request = RubySaml::SloLogoutrequest.new(
    params[:SAMLRequest], settings: settings
  )
  if !logout_request.is_valid?
    logger.error "IdP initiated LogoutRequest was not valid!"
    return render inline: logger.error
  end
  logger.info "IdP initiated Logout for #{logout_request.name_id}"

  # Actually log out this session
  delete_session

  # Generate a response to the IdP.
  logout_request_id = logout_request.id
  logout_response = RubySaml::SloLogoutresponse.new.create(settings, logout_request_id, nil, 'RelayState' => params[:RelayState])
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

### Clock Drift

If during validation of the response you get the error "Current time is earlier than NotBefore condition",
this may be due to clock differences between your system and that of the IdP.

First, ensure that both systems synchronize their clocks, using for example the industry standard
[Network Time Protocol (NTP)](https://en.wikipedia.org/wiki/Network_Time_Protocol).

To allow for a small amount of clock drift, you can initialize the response with the
`:allowed_clock_drift` option, specified in number of seconds. For example:

```ruby
response = RubySaml::Response.new(params[:SAMLResponse], allowed_clock_drift: 1.second)
```

Make sure to keep the value as comfortably small as possible to keep security risks to a minimum.

### Deflation Limit

To protect against decompression bombs (a form of DoS attack), SAML messages are limited to 250,000 bytes by default.
Sometimes legitimate SAML messages will exceed this limit,
for example due to custom claims like including groups a user is a member of.
If you want to customize this limit, you need to provide a different setting when initializing the response object.
Example:

```ruby
def consume
  response = RubySaml::Response.new(params[:SAMLResponse], { settings: saml_settings })
  # ...
end

private

def saml_settings
  RubySaml::Settings.new(message_max_bytesize: 500_000)
end
```

### Attribute Service

To request attributes from the IdP the SP needs to provide an attribute service within its metadata and reference the index in the assertion.

```ruby
settings = RubySaml::Settings.new
settings.attributes_index = 5
settings.attribute_consuming_service.configure do
  service_name "Service"
  service_index 5
  add_attribute name: "Name", name_format: "Name Format", friendly_name: "Friendly Name"
  add_attribute name: "Another Attribute", name_format: "Name Format", friendly_name: "Friendly Name", attribute_value: "Attribute Value"
end
```

The `attribute_value` option additionally accepts an array of possible values.

### SP-Originated Message IDs

Ruby SAML automatically generates message IDs for SP-originated messages (AuthNRequest, etc.)
By default, this is a UUID prefixed by the `_` character, for example `"_ea8b5fdf-0a71-4bef-9f87-5406ee746f5b"`. 
To override this behavior, you may set `settings.sp_uuid_prefix` to a string of your choice.
Note that the SAML specification requires that this type (`xsd:ID`) be an
[NCName](https://www.w3.org/TR/xmlschema-2/#NCName), meaning that it must start with a letter
or underscore, and can only contain letters, digits, underscores, hyphens, and periods.

### Custom Metadata Fields

Some IdPs may require SPs to add additional fields (Organization, ContactPerson, etc.)
into the SP metadata. This can be done by extending the `RubySaml::Metadata` class and
overriding the `#add_extras` method where the first arg is a
[Nokogiri::XML::Builder](https://nokogiri.org/rdoc/Nokogiri/XML/Builder.html) object as per
the following example:

```ruby
class MyMetadata < RubySaml::Metadata
  private

  def add_extras(xml, _settings)
    xml.Organization do
      xml.OrganizationName('xml:lang' => 'en-US') { xml.text 'ACME Inc.' }
      xml.OrganizationDisplayName('xml:lang' => 'en-US') { xml.text 'ACME' }
      xml.OrganizationURL('xml:lang' => 'en-US') { xml.text 'https://www.acme.com' }
    end

    xml.ContactPerson('contactType' => 'technical') do
      xml.GivenName { xml.text 'ACME SAML Team' }
      xml.EmailAddress { xml.text 'saml@acme.com' }
    end
  end
end

# Output XML with custom metadata
MyMetadata.new.generate(settings)
```

### Preventing Replay Attacks

A replay attack is when an attacker intercepts a valid SAML assertion and "replays" it at a later time to gain unauthorized access.

The library only checks the assertion's validity window (`NotBefore` and `NotOnOrAfter` conditions). An attacker can replay a valid assertion as many times as they want within this window.

A robust defense requires tracking of assertion IDs to ensure any given assertion is only accepted once.

#### 1. Extract the Assertion ID after Validation

After a response has been successfully validated, get the assertion ID. The library makes this available via `response.assertion_id`.


#### 2. Store the ID with an Expiry

You must store this ID in a persistent cache (like Redis or Memcached) that is shared across your servers. Do not store it in the user's session, as that is not a secure cache.

The ID should be stored until the assertion's validity window has passed. You will need to check how long the trusted IdPs consider the assertion valid and then add the allowed_clock_drift.

You can define a global value, or set this value dinamically based on the `not_on_or_after` value of the re + `allowed_clock_drift`.

```ruby
# In your `consume` action, after a successful validation:
if response.is_valid?
  # Prevent replay of this specific assertion
  assertion_id = response.assertion_id
  authorize_failure("Assertion ID is mandatory") if assertion_id.nil?

  assertion_not_on_or_after = response.not_on_or_after
  # We set a default of 5 min expiration in case is not provided
  assertion_expiry = (Time.now.utc + 300) if assertion_not_on_or_after.nil?

  # `is_new_assertion?` is your application's method to check and set the ID
  # in a shared, persistent cache (e.g., Redis, Memcached).
  if is_new_assertion?(assertion_id, expires_at: assertion_expiry)
    # This is a new assertion, so we can proceed
    session[:userid] = response.nameid
    session[:attributes] = response.attributes
    # ...
  else
    # This assertion ID has been seen before. This is a REPLAY ATTACK.
    # Log the security event and reject the user.
    authorize_failure("Replay attack detected")
  end
else
  authorize_failure("Invalid response")
end
```

Your `is_new_assertion?` method would look something like this (example for Redis):

```ruby

def is_new_assertion?(assertion_id, expires_at)
  ttl = (expires_at - Time.now.utc).to_i
  return false if ttl <= 0 # The assertion has already expired

  # The 'nx' option tells Redis to only set the key if it does not already exist.
  # The command returns `true` if the key was set, `false` otherwise.
  $redis.set("saml_assertion_ids:#{assertion_id}", "1", ex: ttl, nx: true)
end
```

### Enforce SP-Initiated Flow with `InResponseTo` validation

This is the best way to prevent IdP-initiated logins and ensure that you only accept assertions that you recently requested.

#### 1. Store the `AuthnRequest` ID

When you create an `AuthnRequest`, the library assigns it a unique ID. You must store this ID, for example in the user's session *before* redirecting them to the IdP.

```ruby
def init
  request = OneLogin::RubySaml::Authrequest.new
  # The unique ID of the request is in request.uuid
  session[:saml_request_id] = request.uuid
  redirect_to(request.create(saml_settings))
end
```

#### 2. Validate the `InResponseTo` value of the `Response` with the Stored ID

When you process the `SAMLResponse`, retrieve the ID from the session and pass it to the `Response` constructor. Use `session.delete` to ensure the ID can only be used once.

```ruby
def consume
  request_id = session.delete(:saml_request_id) # Use delete to prevent re-use

  # You can reject the response if no previous saml_request_id was stored
  raise "IdP-initiaited detected" if request_id.nil?

  response = OneLogin::RubySaml::Response.new(
    params[:SAMLResponse],
    settings: saml_settings,
    matches_request_id: request_id
  )

  if response.is_valid?
    # ... authorize user
  else
    # Response is invalid, errors in response.errors
  end
end
```

## Contributing

### Pay it Forward: Support RubySAML and Strengthen Open-Source Security

RubySAML is a trusted authentication library used by startups and enterprises alike—
a community-driven alternative to costly third-party services.

But security doesn't happen in a vacuum. Vulnerabilities in authentication libraries can
have widespread consequences. Maintaining open-source security requires continuous
effort, expertise, and funding. By supporting RubySAML, you’re not just securing your
own systems—you’re strengthening auth security globally. Instead of paying for closed
solutions, consider investing in the community that does the real security work.

#### How you can help

* Sponsor RubySAML: [GitHub Sponsors](https://github.com/sponsors/SAML-Toolkits)
* Contribute to secure-by-design improvements
* Responsibly report vulnerabilities (see "Vulnerability Reporting" above)

Security is a shared responsibility. If RubySAML has helped your organization, please
consider giving back. Together, we can keep authentication secure—without putting it
behind paywalls.

### Adding Features, Pull Requests

* Fork the repository
* Make your feature addition or bug fix
* Add tests for your new features. This is important so we don't break any features in a future version unintentionally.
* Ensure all tests pass by running `bundle exec rake test`.
* Do not change rakefile, version, or history.
* Open a pull request, following [this template](https://gist.github.com/Lordnibbler/11002759).

### Sponsors

Thanks to the following sponsors for securing the open source ecosystem:

#### [<img class="circle" src="https://avatars.githubusercontent.com/u/34724717" width="26" height="26" alt="@serpapi">](https://serpapi.com) [<sup>SerpApi</sup>](https://github.com/serpapi)
<sup>*A real-time API to access Google search results. It handle proxies, solve captchas, and parse all rich structured data for you*</sup>

#### [<img class="circle" src="https://avatars.githubusercontent.com/u/9919" width="26" height="26" alt="@github">](https://github.com/) [<sup>Github</sup>](https://github.com/github)
<sup>*The complete developer platform to build, scale, and deliver secure software.*</sup>

#### [<img alt="84codes" src="https://avatars.githubusercontent.com/u/5353257" width="26" height="26">](https://www.84codes.com) [<sup>84codes</sup>](https://github.com/84codes)
<sup>*Simplifying Message Queuing and Streaming. Leave server management to the experts, so you can focus on building great applications.*</sup>


### Attribution

Portions of the code in `RubySaml::XML` namespace is adapted from earlier work
copyrighted by either Oracle and/or Todd W. Saxton. The original code was distributed
under the Common Development and Distribution License (CDDL) 1.0. This code is
currently in the process of being rewritten.

## License

Ruby SAML is made available under the MIT License. Refer to [LICENSE](LICENSE).

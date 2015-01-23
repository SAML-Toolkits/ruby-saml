# RubySaml Changelog
### 0.9 (Jan 26, 2015)
* [#169](https://github.com/onelogin/ruby-saml/pull/169) WantAssertionSigned should be either true or false
* [#167](https://github.com/onelogin/ruby-saml/pull/167) (doc update) make unit of clock drift obvious
* [#160](https://github.com/onelogin/ruby-saml/pull/160) Extended solution for Attributes method [] can raise NoMethodError
* [#158](https://github.com/onelogin/ruby-saml/pull/1) Added ability to specify attribute services in metadata
* [#154](https://github.com/onelogin/ruby-saml/pull/154) Fix incorrect gem declaration statement
* [#152](https://github.com/onelogin/ruby-saml/pull/152) Fix the PR #99
* [#150](https://github.com/onelogin/ruby-saml/pull/150) Nokogiri already in gemspec
* [#147](https://github.com/onelogin/ruby-saml/pull/147) Fix LogoutResponse issuer validation and implement SAML Response issuer validation.
* [#144](https://github.com/onelogin/ruby-saml/pull/144) Fix DigestMethod lookup bug
* [#139](https://github.com/onelogin/ruby-saml/pull/139) Fixes handling of some soft and hard validation failures
* [#138](https://github.com/onelogin/ruby-saml/pull/138) Change logoutrequest.rb to UTC time
* [#136](https://github.com/onelogin/ruby-saml/pull/136) Remote idp metadata
* [#135](https://github.com/onelogin/ruby-saml/pull/135) Restored support for NIL as well as empty AttributeValues
* [#134](https://github.com/onelogin/ruby-saml/pull/134) explicitly require "onelogin/ruby-saml/logging"
* [#133](https://github.com/onelogin/ruby-saml/pull/133) Added license to gemspec
* [#132](https://github.com/onelogin/ruby-saml/pull/132) Support AttributeConsumingServiceIndex in AuthnRequest
* [#131](https://github.com/onelogin/ruby-saml/pull/131) Add ruby 2.1.1 to .travis.yml
* [#122](https://github.com/onelogin/ruby-saml/pull/122) Fixes #112 and #117 in a backwards compatible manner
* [#119](https://github.com/onelogin/ruby-saml/pull/119) Add support for extracting IdP details from metadata xml

### 0.8.2 (Jan 26, 2015)
* [#183](https://github.com/onelogin/ruby-saml/pull/183) Resolved a security vulnerability where string interpolation in a `REXML::XPath.first()` method call allowed for arbitrary code execution.

### 0.8.0 (Feb 21, 2014)
**IMPORTANT**: This release changed namespace of the gem from `OneLogin::Saml` to `OneLogin::RubySaml`.  Please update your implementations of the gem accordingly.

* [#111](https://github.com/onelogin/ruby-saml/pull/111) `Onelogin::` is `OneLogin::`
* [#108](https://github.com/onelogin/ruby-saml/pull/108) Change namespacing from `Onelogin::Saml` to `Onelogin::Rubysaml`


### 0.7.3 (Feb 20, 2014)
Updated gem dependencies to be compatible with Ruby 1.8.7-p374 and 1.9.3-p448. Removed unnecessary `canonix` gem dependency.

* [#107](https://github.com/onelogin/ruby-saml/pull/107) Relax nokogiri version requirement to >= 1.5.0
* [#105](https://github.com/onelogin/ruby-saml/pull/105) Lock Gem versions, fix to resolve possible namespace collision

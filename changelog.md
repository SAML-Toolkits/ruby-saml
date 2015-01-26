# RubySaml Changelog

### 0.8.2 (Jan 26, 2014)
* [#183](https://github.com/onelogin/ruby-saml/pull/183) Resolved a security vulnerability where string interpolation in a `REXML::XPath.first()` method call allowed for arbitrary code execution.

### 0.8.0 (Feb 21, 2014)
**IMPORTANT**: This release changed namespace of the gem from `OneLogin::Saml` to `OneLogin::RubySaml`.  Please update your implementations of the gem accordingly.

* [#111](https://github.com/onelogin/ruby-saml/pull/111) `Onelogin::` is `OneLogin::`
* [#108](https://github.com/onelogin/ruby-saml/pull/108) Change namespacing from `Onelogin::Saml` to `Onelogin::Rubysaml`


### 0.7.3 (Feb 20, 2014)
Updated gem dependencies to be compatible with Ruby 1.8.7-p374 and 1.9.3-p448. Removed unnecessary `canonix` gem dependency.

* [#107](https://github.com/onelogin/ruby-saml/pull/107) Relax nokogiri version requirement to >= 1.5.0
* [#105](https://github.com/onelogin/ruby-saml/pull/105) Lock Gem versions, fix to resolve possible namespace collision

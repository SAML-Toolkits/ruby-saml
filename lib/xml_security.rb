# frozen_string_literal: true

require 'ruby_saml/logging'
RubySaml::Logging.deprecate 'Using `require "xml_security"` is deprecated and will be removed ' \
                            'in RubySaml 2.1.0. Instead, please `require "ruby-saml"` and use ' \
                            'the modules in RubySaml::XML instead.'

# @deprecated This file adds compatibility with v1.x and will be removed in v2.1.0
require 'ruby_saml/xml/deprecated'

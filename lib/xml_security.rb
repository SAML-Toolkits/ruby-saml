# frozen_string_literal: true

require 'ruby_saml/logging'
RubySaml::Logging.deprecate 'Using `require "xml_security"` is deprecated and will be removed ' \
                            'in RubySaml 3.0.0. Instead, please `require "ruby-saml"` and use ' \
                            'the modules in RubySaml::XML instead.'

# @deprecated This file adds compatibility with v1.x and will be removed in v3.0.0
require 'ruby_saml/xml'

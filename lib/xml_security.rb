# frozen_string_literal: true

require 'ruby_saml/logging'
RubySaml::Logging.deprecate 'Using `require "xml_security"` is deprecated and will be removed ' \
                            'in RubySaml 2.1.0. Please use `require "ruby_saml/xml"` instead.'

# @deprecated This file adds compatibility with v1.x and will be removed in v2.1.0
require 'ruby_saml/xml'

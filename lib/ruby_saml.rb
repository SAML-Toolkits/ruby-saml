# frozen_string_literal: true

require 'cgi'
require 'zlib'
require 'base64'
require 'time'
require 'nokogiri'

require 'ruby_saml/logging'
require 'ruby_saml/xml'
require 'ruby_saml/settings'

require 'ruby_saml/sp/builders/message_builder'
require 'ruby_saml/sp/builders/authn_request'
require 'ruby_saml/sp/builders/logout_request'
require 'ruby_saml/sp/builders/logout_response'
require 'ruby_saml/metadata'

# TODO: Extract errors to have common base class
require 'ruby_saml/setting_error'
require 'ruby_saml/http_error'
require 'ruby_saml/validation_error'

require 'ruby_saml/attribute_service'
require 'ruby_saml/attributes'
require 'ruby_saml/saml_message'
require 'ruby_saml/response'
require 'ruby_saml/logoutresponse'
require 'ruby_saml/slo_logoutrequest'
require 'ruby_saml/idp_metadata_parser'

require 'ruby_saml/pem_formatter'
require 'ruby_saml/utils'
require 'ruby_saml/version'

# @deprecated This alias adds compatibility with v1.x and will be removed in v2.1.0
OneLogin = Object

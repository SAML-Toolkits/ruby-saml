# frozen_string_literal: true

require 'rexml/document'
require 'rexml/security'
require 'rexml/xpath'
require 'nokogiri'
require 'openssl'
require 'digest/sha1'
require 'digest/sha2'

module RubySaml
  module XML
    class BaseDocument < REXML::Document
      # TODO: This affects the global state
      REXML::Security.entity_expansion_limit = 0

      # @deprecated Constants moved to Crypto module
      C14N = RubySaml::XML::C14N
      DSIG = RubySaml::XML::DSIG
      NOKOGIRI_OPTIONS = RubySaml::XML::NOKOGIRI_OPTIONS

      # @deprecated Remove in v2.1.0
      def canon_algorithm(algorithm)
        RubySaml::XML.canon_algorithm(algorithm)
      end

      # @deprecated Remove in v2.1.0
      def algorithm(algorithm)
        RubySaml::XML.hash_algorithm(algorithm)
      end
    end
  end
end

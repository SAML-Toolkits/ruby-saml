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
    # @deprecated Will be removed soon.
    class BaseDocument < REXML::Document
      # TODO: This affects the global state
      REXML::Security.entity_expansion_limit = 0

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

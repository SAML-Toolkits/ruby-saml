# frozen_string_literal: true

require 'nokogiri'
require 'openssl'
require 'digest/sha1'
require 'digest/sha2'
require 'ruby_saml/xml/crypto'

module RubySaml
  module XML
    class BaseDocument < Nokogiri::XML::Document
      # @deprecated Constants moved to Crypto module
      C14N = RubySaml::XML::Crypto::C14N
      DSIG = RubySaml::XML::Crypto::DSIG

      NOKOGIRI_OPTIONS = Nokogiri::XML::ParseOptions::STRICT |
                         Nokogiri::XML::ParseOptions::NONET

      # @deprecated Remove in v2.1.0
      def canon_algorithm(algorithm)
        RubySaml::XML::Crypto.canon_algorithm(algorithm)
      end

      # @deprecated Remove in v2.1.0
      def algorithm(algorithm)
        RubySaml::XML::Crypto.hash_algorithm(algorithm)
      end
    end
  end
end
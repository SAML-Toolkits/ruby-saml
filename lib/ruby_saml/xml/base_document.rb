# frozen_string_literal: true

require 'nokogiri'
require 'openssl'
require 'digest/sha1'
require 'digest/sha2'
require 'ruby_saml/xml/crypto'

module RubySaml
  module XML

    # TODO: Remove this in favor of using Nokogiri::XML::Document directly
    # Convert Document class to DocumentSigner
    # and convert SignedDocument class to SignedDocumentValidator
    class BaseDocument < Nokogiri::XML::Document
      # @deprecated Constants moved to Crypto module
      C14N = RubySaml::XML::Crypto::C14N
      DSIG = RubySaml::XML::Crypto::DSIG

      NOKOGIRI_OPTIONS = Nokogiri::XML::ParseOptions::STRICT |
                         Nokogiri::XML::ParseOptions::NONET

      # def initialize(xml = nil)
      #   @document = xml ? Nokogiri::XML(xml, nil, nil, NOKOGIRI_OPTIONS) : Nokogiri::XML::Document,.new { |config| config.strict.nonet }
      # end

      # def xpath(query, namespaces = {})
      #   @document.xpath(query, namespaces)
      # end
      #
      # def at_xpath(query, namespaces = {})
      #   @document.at_xpath(query, namespaces)
      # end
      #
      # def to_s
      #   @document.to_xml
      # end

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

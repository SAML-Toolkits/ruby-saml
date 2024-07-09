# frozen_string_literal: true

require 'rexml/document'
require 'rexml/xpath'
require 'nokogiri'
require 'openssl'
require 'digest/sha1'
require 'digest/sha2'

module RubySaml
  module XML
    class BaseDocument < REXML::Document
      REXML::Document.entity_expansion_limit = 0

      C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
      DSIG = 'http://www.w3.org/2000/09/xmldsig#'
      NOKOGIRI_OPTIONS = Nokogiri::XML::ParseOptions::STRICT |
                         Nokogiri::XML::ParseOptions::NONET

      def canon_algorithm(element)
        algorithm = element
        if algorithm.is_a?(REXML::Element)
          algorithm = element.attribute('Algorithm').value
        end

        case algorithm
        when 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
             'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments'
          Nokogiri::XML::XML_C14N_1_0
        when 'http://www.w3.org/2006/12/xml-c14n11',
             'http://www.w3.org/2006/12/xml-c14n11#WithComments'
          Nokogiri::XML::XML_C14N_1_1
        else
          Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
        end
      end

      def algorithm(element)
        algorithm = element
        if algorithm.is_a?(REXML::Element)
          algorithm = element.attribute('Algorithm').value
        end

        algorithm = algorithm && algorithm =~ /(rsa-)?sha(.*?)$/i && ::Regexp.last_match(2).to_i

        case algorithm
        when 1 then OpenSSL::Digest::SHA1
        when 384 then OpenSSL::Digest::SHA384
        when 512 then OpenSSL::Digest::SHA512
        else
          OpenSSL::Digest::SHA256
        end
      end
    end
  end
end

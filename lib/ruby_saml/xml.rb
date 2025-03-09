# frozen_string_literal: true

require 'rexml/element'
require 'openssl'
require 'nokogiri'
require 'digest/sha1'
require 'digest/sha2'

module RubySaml
  module XML
    extend self

    # XML constants
    #
    # @api private
    C14N          = 'http://www.w3.org/2001/10/xml-exc-c14n#'
    DSIG          = 'http://www.w3.org/2000/09/xmldsig#'
    RSA_SHA1      = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    RSA_SHA224    = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224'
    RSA_SHA256    = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    RSA_SHA384    = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
    RSA_SHA512    = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
    DSA_SHA1      = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
    DSA_SHA256    = 'http://www.w3.org/2009/xmldsig11#dsa-sha256'
    ECDSA_SHA1    = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1'
    ECDSA_SHA224  = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224'
    ECDSA_SHA256  = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'
    ECDSA_SHA384  = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384'
    ECDSA_SHA512  = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512'
    SHA1          = 'http://www.w3.org/2000/09/xmldsig#sha1'
    SHA224        = 'http://www.w3.org/2001/04/xmldsig-more#sha224'
    SHA256        = 'http://www.w3.org/2001/04/xmlenc#sha256'
    SHA384        = 'http://www.w3.org/2001/04/xmldsig-more#sha384'
    SHA512        = 'http://www.w3.org/2001/04/xmlenc#sha512'
    ENVELOPED_SIG = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'

    NOKOGIRI_OPTIONS = Nokogiri::XML::ParseOptions::STRICT |
                       Nokogiri::XML::ParseOptions::NONET

    # Find XML canonicalization algorithm
    #
    # @api private
    def canon_algorithm(element, default: true)
      case get_algorithm_attr(element)
      when %r{\Ahttp://www\.w3\.org/TR/2001/REC-xml-c14n-20010315#?(?:WithComments)?\z}i
        Nokogiri::XML::XML_C14N_1_0
      when %r{\Ahttp://www\.w3\.org/2006/12/xml-c14n11#?(?:WithComments)?\z}i
        Nokogiri::XML::XML_C14N_1_1
      when %r{\Ahttp://www\.w3\.org/2001/10/xml-exc-c14n#?(?:WithComments)?\z}i
        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      else
        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0 if default
      end
    end

    # Find XML signature algorithm
    #
    # @api private
    def signature_algorithm(element)
      alg = get_algorithm_attr(element)
      match_data = alg&.downcase&.match(/(?:\A|#)(rsa|dsa|ecdsa)-(sha\d+)\z/i) || {}
      key_alg  = match_data[1]
      hash_alg = match_data[2]

      key = case key_alg
            when 'rsa'   then OpenSSL::PKey::RSA
            when 'dsa'   then OpenSSL::PKey::DSA
            when 'ecdsa' then OpenSSL::PKey::EC
            else # rubocop:disable Lint/DuplicateBranch
              # TODO: raise ArgumentError.new("Invalid key algorithm: #{alg}")
              OpenSSL::PKey::RSA
            end

      [key, hash_algorithm(hash_alg)]
    end

    # Find XML digest hashing algorithm
    #
    # @api private
    def hash_algorithm(element)
      alg = get_algorithm_attr(element)
      hash_alg = alg&.downcase&.match(/(?:\A|[#-])(sha\d+)\z/i)&.[](1)

      case hash_alg
      when 'sha1' then OpenSSL::Digest::SHA1
      when 'sha224' then OpenSSL::Digest::SHA224
      when 'sha256' then OpenSSL::Digest::SHA256
      when 'sha384' then OpenSSL::Digest::SHA384
      when 'sha512' then OpenSSL::Digest::SHA512
      else # rubocop:disable Lint/DuplicateBranch
        # TODO: raise ArgumentError.new("Invalid hash algorithm: #{alg}")
        OpenSSL::Digest::SHA256
      end
    end

    private

    def get_algorithm_attr(element)
      if element.is_a?(Nokogiri::XML::Element)
        element['Algorithm']
      elsif element.is_a?(REXML::Element)
        element.attribute('Algorithm').value
      elsif element
        element
      end
    end
  end
end

require 'ruby_saml/xml/base_document'
require 'ruby_saml/xml/document'
require 'ruby_saml/xml/signed_document'

# @deprecated This alias adds compatibility with v1.x and will be removed in v2.1.0
unless defined?(XMLSecurity)
  XMLSecurity = RubySaml::XML
end

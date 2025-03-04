# frozen_string_literal: true

require 'ruby_saml/xml/crypto'
require 'ruby_saml/xml/document_signer'
require 'ruby_saml/xml/signed_document_validator'

# @deprecated This alias adds compatibility with v1.x and will be removed in v2.1.0
XMLSecurity = RubySaml::XML

# @deprecated These are preserved for constants and methods, and will be removed in v2.1.0
module RubySaml
  module XML
    module BaseDocument
      # @deprecated Constants moved to Crypto module
      C14N = RubySaml::XML::Crypto::C14N
      DSIG = RubySaml::XML::Crypto::DSIG

      NOKOGIRI_OPTIONS = Nokogiri::XML::ParseOptions::STRICT |
        Nokogiri::XML::ParseOptions::NONET

      # @deprecated Remove in v2.1.0
      def self.canon_algorithm(algorithm)
        RubySaml::XML::Crypto.canon_algorithm(algorithm)
      end

      # @deprecated Remove in v2.1.0
      def self.algorithm(algorithm)
        RubySaml::XML::Crypto.hash_algorithm(algorithm)
      end
    end

    module Document
      INC_PREFIX_LIST = '#default samlp saml ds xs xsi md'

      # @deprecated Constants moved to Crypto module
      RSA_SHA1      = RubySaml::XML::Crypto::RSA_SHA1
      RSA_SHA224    = RubySaml::XML::Crypto::RSA_SHA224
      RSA_SHA256    = RubySaml::XML::Crypto::RSA_SHA256
      RSA_SHA384    = RubySaml::XML::Crypto::RSA_SHA384
      RSA_SHA512    = RubySaml::XML::Crypto::RSA_SHA512
      DSA_SHA1      = RubySaml::XML::Crypto::DSA_SHA1
      DSA_SHA256    = RubySaml::XML::Crypto::DSA_SHA256
      ECDSA_SHA1    = RubySaml::XML::Crypto::ECDSA_SHA1
      ECDSA_SHA224  = RubySaml::XML::Crypto::ECDSA_SHA224
      ECDSA_SHA256  = RubySaml::XML::Crypto::ECDSA_SHA256
      ECDSA_SHA384  = RubySaml::XML::Crypto::ECDSA_SHA384
      ECDSA_SHA512  = RubySaml::XML::Crypto::ECDSA_SHA512
      SHA1          = RubySaml::XML::Crypto::SHA1
      SHA224        = RubySaml::XML::Crypto::SHA224
      SHA256        = RubySaml::XML::Crypto::SHA256
      SHA384        = RubySaml::XML::Crypto::SHA384
      SHA512        = RubySaml::XML::Crypto::SHA512
      ENVELOPED_SIG = RubySaml::XML::Crypto::ENVELOPED_SIG
    end
  end
end

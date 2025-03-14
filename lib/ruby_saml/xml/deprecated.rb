# frozen_string_literal: true

unless defined?(XMLSecurity)
  require 'rexml/document'
  require 'ruby_saml/logging'

  REXML::Security.entity_expansion_limit = 0

  module XMLSecurity
    # @deprecated Will be removed in v2.1.0.
    # @api private
    class BaseDocument < REXML::Document
      # @deprecated Constants
      C14N = RubySaml::XML::C14N
      DSIG = RubySaml::XML::DSIG
      NOKOGIRI_OPTIONS = RubySaml::XML::NOKOGIRI_OPTIONS

      # @deprecated Will be removed in v2.1.0.
      def canon_algorithm(algorithm)
        RubySaml::Logging.deprecate 'XMLSecurity::BaseDocument#canon_algorithm is deprecated and will be removed in v2.1.0. ' \
                                    'Use RubySaml::XML.canon_algorithm instead.'
        RubySaml::XML.canon_algorithm(algorithm)
      end

      # @deprecated Will be removed in v2.1.0.
      def algorithm(algorithm)
        RubySaml::Logging.deprecate 'XMLSecurity::BaseDocument#algorithm is deprecated and will be removed in v2.1.0. ' \
                                    'Use RubySaml::XML.hash_algorithm instead.'
        RubySaml::XML.hash_algorithm(algorithm)
      end
    end

    # @deprecated Will be removed in v2.1.0.
    # @api private
    class Document < BaseDocument
      # @deprecated Constants
      INC_PREFIX_LIST = RubySaml::XML::DocumentSigner::INC_PREFIX_LIST
      RSA_SHA1      = RubySaml::XML::RSA_SHA1
      RSA_SHA224    = RubySaml::XML::RSA_SHA224
      RSA_SHA256    = RubySaml::XML::RSA_SHA256
      RSA_SHA384    = RubySaml::XML::RSA_SHA384
      RSA_SHA512    = RubySaml::XML::RSA_SHA512
      DSA_SHA1      = RubySaml::XML::DSA_SHA1
      DSA_SHA256    = RubySaml::XML::DSA_SHA256
      ECDSA_SHA1    = RubySaml::XML::ECDSA_SHA1
      ECDSA_SHA224  = RubySaml::XML::ECDSA_SHA224
      ECDSA_SHA256  = RubySaml::XML::ECDSA_SHA256
      ECDSA_SHA384  = RubySaml::XML::ECDSA_SHA384
      ECDSA_SHA512  = RubySaml::XML::ECDSA_SHA512
      SHA1          = RubySaml::XML::SHA1
      SHA224        = RubySaml::XML::SHA224
      SHA256        = RubySaml::XML::SHA256
      SHA384        = RubySaml::XML::SHA384
      SHA512        = RubySaml::XML::SHA512
      ENVELOPED_SIG = RubySaml::XML::ENVELOPED_SIG

      # @deprecated Will be removed in v2.1.0.
      def initialize(*args, **_kwargs)
        RubySaml::Logging.deprecate 'XMLSecurity::Document is deprecated and will be removed in v2.1.0. ' \
                                    'Use RubySaml::XML::DocumentSigner.sign_document instead.'
        super(args[0])
      end

      # @deprecated Will be removed in v2.1.0.
      def sign_document(*_args, **_kwargs)
        msg = 'XMLSecurity::Document#sign_document has been removed. ' \
              'Use RubySaml::XML::DocumentSigner.sign_document instead.'
        raise ::NoMethodError.new(msg)
      end
    end

    # @deprecated Will be removed in v2.1.0.
    # @api private
    class SignedDocument < BaseDocument
      # @deprecated Will be removed in v2.1.0.
      def initialize(*args, **_kwargs)
        RubySaml::Logging.deprecate 'XMLSecurity::SignedDocument is deprecated and will be removed in v2.1.0.' \
                                    'Use RubySaml::XML::SignedDocumentValidator.validate_document instead.'
        super(args[0])
      end

      # @deprecated Will be removed in v2.1.0.
      def validate_document(*_args, **_kwargs)
        msg = 'XMLSecurity::SignedDocument#validate_document has been removed. ' \
              'Use RubySaml::XML::SignedDocumentValidator.validate_document instead.'
        raise ::NoMethodError.new(msg)
      end

      # @deprecated Will be removed in v2.1.0.
      def extract_inclusive_namespaces
        msg = 'XMLSecurity::SignedDocument#extract_inclusive_namespaces has been removed.'
        raise ::NoMethodError.new(msg)
      end
    end
  end
end

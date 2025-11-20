# frozen_string_literal: true

require 'ruby_saml/error_handling'
require 'ruby_saml/utils'

module RubySaml
  module XML
    # Wrapper for the SignedDocumentInfo class.
    # TODO: This should be refactored and removed
    module SignedDocumentValidator
      extend self

      def with_error_handling(errors, soft)
        yield
      rescue RubySaml::ValidationError => e
        errors << e.message
        raise e unless soft

        errors # TODO: Return false??
      end

      # TODO: [ERRORS-REFACTOR] -- Rather than returning array of error,
      # raise actual error classes
      def validate_document(document, idp_cert_fingerprint, errors = [], soft: true, **options)
        with_error_handling(errors, soft) do
          SignedDocumentInfo.new(document).validate_document(idp_cert_fingerprint, options)
        end
      end

      def validate_document_with_cert(document, idp_cert, errors = [], soft: true)
        with_error_handling(errors, soft) do
          SignedDocumentInfo.new(document).validate_document_with_cert(idp_cert)
        end
      end

      def validate_signature(document, base64_cert, errors = [], soft: true)
        with_error_handling(errors, soft) do
          SignedDocumentInfo.new(document).validate_signature(base64_cert)
        end
      end

      # TODO: This is a workaround to avoid errors
      def subject_id(document)
        SignedDocumentInfo.new(document).subject_id
      rescue RubySaml::ValidationError
        # TODO: Consider removing the error in SignedDocumentInfo#subject_id
      end

      def subject_node(document)
        SignedDocumentInfo.new(document).subject_node
      end
    end
  end
end

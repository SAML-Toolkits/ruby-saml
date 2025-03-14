# frozen_string_literal: true

require 'ruby_saml/error_handling'
require 'ruby_saml/utils'

module RubySaml
  module XML
    module SignedDocumentValidator
      extend self

      # TODO: [ERRORS-REFACTOR] -- Rather than returning array of error,
      # raise actual error classes
      def validate_document(document, idp_cert_fingerprint, soft: true, **options)

        # get cert from response
        noko = RubySaml::XML.safe_load_nokogiri(document.to_s)

        cert_element = noko.at_xpath(
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::DSIG }
        )

        if cert_element
          base64_cert = cert_element&.content
          cert_text = Base64.decode64(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue OpenSSL::X509::CertificateError => _e
            # TODO: [ERRORS-REFACTOR] Refactor to Errors::CertificateInvalid
            return 'Document Certificate Error'
          end

          if options[:fingerprint_alg]
            fingerprint_alg = RubySaml::XML.hash_algorithm(options[:fingerprint_alg]).new
          else
            fingerprint_alg = OpenSSL::Digest.new('SHA256')
          end
          fingerprint = fingerprint_alg.hexdigest(cert.to_der)

          # check cert matches registered idp cert
          if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,'').downcase
            # TODO: [ERRORS-REFACTOR] Refactor to Errors::FingerprintMismatch
            return 'Fingerprint mismatch'
          end
        elsif options[:cert]
          base64_cert = Base64.encode64(options[:cert].to_pem)
        else
          # TODO: [ERRORS-REFACTOR] Refactor to Errors::CertificateElementMissing
          # TODO: Return false if soft -- why?
          return soft ? false : 'Certificate element missing in response (ds:X509Certificate) and not cert provided at settings'
        end

        validate_signature(document, base64_cert)
      end

      def validate_document_with_cert(document, idp_cert)

        # Get document as Nokogiri document
        noko = RubySaml::XML.safe_load_nokogiri(document.to_s)

        # get cert from response
        cert_element = noko.at_xpath(
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::DSIG }
        )

        if cert_element
          base64_cert = cert_element&.content
          cert_text = Base64.decode64(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue OpenSSL::X509::CertificateError => _e
            # TODO: [ERRORS-REFACTOR] Refactor to Errors::CertificateInvalid
            return 'Document Certificate Error'
          end

          # check saml response cert matches provided idp cert
          if idp_cert.to_pem != cert.to_pem
            # TODO: [ERRORS-REFACTOR] Refactor to Errors::CertificateMismatch
            return 'Certificate of the Signature element does not match provided certificate'
          end
        else
          base64_cert = Base64.encode64(idp_cert.to_pem)
        end

        validate_signature(document, base64_cert)
      end

      def validate_signature(document, base64_cert)

        # Create a copy of the document for validation
        noko = RubySaml::XML.safe_load_nokogiri(document.to_s)

        # get signature node
        sig_element = noko.at_xpath(
          '//ds:Signature',
          { 'ds' => RubySaml::XML::DSIG }
        )

        # signature method
        sig_alg_value = sig_element.at_xpath(
          './ds:SignedInfo/ds:SignatureMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        signature_hash_algorithm = RubySaml::XML.hash_algorithm(sig_alg_value)

        # get signature
        base64_signature = sig_element.at_xpath(
          './ds:SignatureValue',
          { 'ds' => RubySaml::XML::DSIG}
        )&.content
        signature = Base64.decode64(base64_signature)

        # canonicalization method
        canon_method_node = sig_element.at_xpath(
          './ds:SignedInfo/ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        canon_algorithm = RubySaml::XML.canon_algorithm(canon_method_node)

        noko_sig_element = noko.at_xpath('//ds:Signature', 'ds' => RubySaml::XML::DSIG)
        noko_signed_info_element = noko_sig_element.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::DSIG)

        canon_string = noko_signed_info_element.canonicalize(canon_algorithm)
        noko_sig_element.remove

        # get signed info
        signed_info_element = sig_element.at_xpath(
          './ds:SignedInfo',
          { 'ds' => RubySaml::XML::DSIG }
        )

        # get inclusive namespaces
        inclusive_namespaces = extract_inclusive_namespaces(document)

        # get signed element id
        signed_element_id = extract_signed_element_id(document)

        # check digests
        ref = signed_info_element.at_xpath(
          './ds:Reference',
          { 'ds' => RubySaml::XML::DSIG }
        )

        reference_nodes = noko.xpath('//*[@ID=$id]', nil, { 'id' => signed_element_id })

        # ensure no elements with same ID to prevent signature wrapping attack.
        if reference_nodes.length > 1
          # TODO: [ERRORS-REFACTOR] Refactor to Errors::DigestDuplicateId
          return 'Digest mismatch. Duplicated ID found'
        end

        hashed_element = reference_nodes[0]

        canon_method_node = signed_info_element.at_xpath(
          './ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        canon_algorithm = RubySaml::XML.canon_algorithm(canon_method_node)

        canon_algorithm = process_transforms(ref, canon_algorithm)

        canon_hashed_element = hashed_element.canonicalize(canon_algorithm, inclusive_namespaces)
        canon_hashed_element.gsub!(/>\s+</, '><')

        digest_method_node = ref.at_xpath(
          './ds:DigestMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        digest_algorithm = RubySaml::XML.hash_algorithm(digest_method_node)
        hash = digest_algorithm.digest(canon_hashed_element)

        encoded_digest_value = ref.at_xpath(
          './ds:DigestValue',
          { 'ds' => RubySaml::XML::DSIG }
        )&.content
        digest_value = Base64.decode64(encoded_digest_value)

        unless digests_match?(hash, digest_value)
          # TODO: [ERRORS-REFACTOR] Refactor to Errors::DigestMismatch
          return 'Digest mismatch'
        end

        # get certificate object
        cert_text = Base64.decode64(base64_cert)
        cert = OpenSSL::X509::Certificate.new(cert_text)

        # verify signature
        signature_verified = false
        begin
          signature_verified = cert.public_key.verify(signature_hash_algorithm.new, signature, canon_string)
        rescue OpenSSL::PKey::PKeyError # rubocop:disable Lint/SuppressedException
        end

        unless signature_verified
          # TODO: [ERRORS-REFACTOR] Refactor to Errors::SignatureVerificationFailed
          return 'Key validation error'
        end

        true
      end

      def extract_signed_element_id(document)
        noko = RubySaml::XML.safe_load_nokogiri(document.to_s)

        reference_element = noko.at_xpath(
          '//ds:Signature/ds:SignedInfo/ds:Reference',
          { 'ds' => RubySaml::XML::DSIG }
        )

        return nil if reference_element.nil?

        uri = reference_element['URI']
        return nil unless uri

        sei = uri[1..]  # Remove the leading '#'
        sei.nil? ? reference_element.parent.parent.parent['ID'] : sei
      end

      private

      def process_transforms(ref, canon_algorithm)
        transforms = ref.xpath(
          './ds:Transforms/ds:Transform',
          { 'ds' => RubySaml::XML::DSIG }
        )

        transforms.each do |transform_element|
          next unless transform_element['Algorithm']

          canon_algorithm = RubySaml::XML.canon_algorithm(transform_element, default: false)
        end

        canon_algorithm
      end

      def digests_match?(hash, digest_value)
        hash == digest_value
      end

      def extract_inclusive_namespaces(document)
        noko = RubySaml::XML.safe_load_nokogiri(document.to_s)

        element = noko.at_xpath(
          '//ec:InclusiveNamespaces',
          { 'ec' => RubySaml::XML::C14N }
        )
        return unless element

        prefix_list = element['PrefixList']
        prefix_list.split
      end
    end
  end
end

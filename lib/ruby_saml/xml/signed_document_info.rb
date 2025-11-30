# frozen_string_literal: true

module RubySaml
  module XML
    # Represents the information extracted from a signed document.
    class SignedDocumentInfo
      attr_reader :noko,
                  :check_malformed_doc

      # Represents the information extracted from a signed document.
      # Intended to avoid signature wrapping attacks.
      #
      # @param noko [Nokogiri::XML] The XML document to validate
      # @param check_malformed_doc [Boolean] Whether to check for malformed documents
      def initialize(noko, check_malformed_doc: true)
        noko = if noko.is_a?(Nokogiri::XML::Document)
                 RubySaml::XML.copy_xml(noko)
               else
                  begin
                    @document = RubySaml::XML.safe_load_xml(noko, check_malformed_doc: check_malformed_doc)
                  rescue StandardError => e
                    raise ValidationError.new("XML load failed: #{e.message}") if e.message != "Empty document"
                  end
               end
        @noko = noko
        @check_malformed_doc = check_malformed_doc
      end

      # Validates the subject_node, which is the signed part of the document
      def validate_document(idp_cert_fingerprint, options = {})
        # Get certificate from document
        if certificate_object
          # Calculate fingerprint using specified algorithm
          fingerprint = certificate_fingerprint(options[:fingerprint_alg] || 'SHA256')

          # Check cert matches registered idp cert fingerprint
          raise RubySaml::ValidationError.new('Fingerprint mismatch') if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/, '').downcase

          cert = certificate_object
        elsif options[:cert]
          cert = options[:cert]
        else
          raise RubySaml::ValidationError.new('Certificate element missing in response (ds:X509Certificate) and no cert provided in settings')
        end

        validate_signature(cert)
      end

      def validate_document_with_cert(idp_cert)
        # Check saml response cert matches provided idp cert
        raise RubySaml::ValidationError.new('Certificate of the Signature element does not match provided certificate') if certificate_object&.to_pem&.!=(idp_cert.to_pem)

        validate_signature(idp_cert)
      end

      def validate_signature(cert)
        # TODO: Remove this
        # Get certificate object
        cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert)) if cert.is_a?(String)

        # Compare digest
        calculated_digest = digest_algorithm.digest(canonicalized_subject)
        raise RubySaml::ValidationError.new('Digest mismatch') unless calculated_digest == digest_value

        # Verify signature
        signature_verified = false
        begin
          signature_verified = cert.public_key.verify(signature_hash_algorithm.new,
                                                      signature_value,
                                                      canonicalized_signed_info)
        rescue OpenSSL::PKey::PKeyError # rubocop:disable Lint/SuppressedException
        end
        raise RubySaml::ValidationError.new('Key validation error') unless signature_verified

        true
      end

      # Get the signature hash algorithm
      # @return [OpenSSL::Digest] The signature hash algorithm
      def signature_hash_algorithm
        sig_alg_value = signed_info_node.at_xpath(
          './ds:SignatureMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        RubySaml::XML.hash_algorithm(sig_alg_value)
      end

      # Get the decoded SignatureValue
      # @return [String] The decoded signature value
      def signature_value
        base64_signature = signature_node.at_xpath(
          './ds:SignatureValue',
          { 'ds' => RubySaml::XML::DSIG }
        )&.text&.strip
        raise RubySaml::ValidationError.new('No Signature Value found') if base64_signature.nil?

        Base64.decode64(base64_signature)
      end

      # Get the canonicalized SignedInfo element
      # @return [String] The canonicalized SignedInfo element
      def canonicalized_signed_info
        @canonicalized_signed_info ||= signed_info_node.canonicalize(canon_algorithm_from_signed_info)
      end

      # Get the Reference node
      # @return [Nokogiri::XML::Element] The Reference node
      def reference_node
        signed_info_node.at_xpath('./ds:Reference', { 'ds' => RubySaml::XML::DSIG }) ||
          (raise RubySaml::ValidationError.new('No Reference node found'))
      end

      # Get the ID of the signed element
      # @return [String] The ID of the signed element
      def subject_id
        # TODO: The error here is problematic, perhaps it can be checked elsewhere
        @subject_id ||= extract_subject_id || (raise RubySaml::ValidationError.new('No signed subject ID found'))
      end

      # Get the subject node (the node being signed)
      # @return [Nokogiri::XML::Element] The subject
      def subject_node
        noko.at_xpath('//*[@ID=$id]', nil, { 'id' => subject_id }) ||
          (raise RubySaml::ValidationError.new('No subject node found'))
      end

      # Get the canonicalized subject node (the node being signed)
      # @return [String] The canonicalized subject
      def canonicalized_subject
        remove_signature_node!
        subject_node.canonicalize(canon_algorithm, inclusive_namespaces)
      end

      # TODO: Destructive side-effect!! signature_node.remove
      # should possibly deep copy the noko object initially
      def remove_signature_node!
        # memoize various elements
        subject_id
        inclusive_namespaces
        canonicalized_signed_info

        signature_node.remove
      end

      # Get the digest algorithm
      # @return [OpenSSL::Digest] The digest algorithm
      def digest_algorithm
        digest_method_node = reference_node.at_xpath(
          './ds:DigestMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        RubySaml::XML.hash_algorithm(digest_method_node)
      end

      # Get the decoded DigestValue
      # @return [String] The decoded digest value
      def digest_value
        encoded_digest = reference_node.at_xpath(
          './ds:DigestValue',
          { 'ds' => RubySaml::XML::DSIG }
        )&.text&.strip
        raise RubySaml::ValidationError.new('No DigestValue found') if encoded_digest.nil?

        Base64.decode64(encoded_digest)
      end

      def certificate_text
        cert = noko.at_xpath(
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::DSIG }
        )&.text&.strip
        Base64.decode64(cert) if cert && !cert.empty?
      end

      # Get the certificate from the document
      # @return [OpenSSL::X509::Certificate] The certificate
      def certificate_object
        return unless certificate_text

        OpenSSL::X509::Certificate.new(certificate_text)
      rescue OpenSSL::X509::CertificateError => _e
        # TODO: include underlying error
        raise RubySaml::ValidationError.new('Document Certificate Error')
      end

      # Calculate the fingerprint of the certificate
      # @param algorithm [String, Symbol] The algorithm to use for fingerprinting
      # @return [String] The fingerprint
      def certificate_fingerprint(algorithm = 'SHA256')
        cert = certificate_object
        return nil unless cert

        fingerprint_alg = RubySaml::XML.hash_algorithm(algorithm).new
        fingerprint_alg.hexdigest(cert.to_der).gsub(/[^a-zA-Z0-9]/, '').downcase
      end

      # Extract inclusive namespaces from the document
      # @return [Array<String>, nil] The inclusive namespaces
      def inclusive_namespaces
        @inclusive_namespaces ||= noko.at_xpath(
          '//ec:InclusiveNamespaces',
          { 'ec' => RubySaml::XML::C14N }
        )&.[]('PrefixList')&.split
      end

      private

      def extract_subject_id
        return unless reference_node

        reference_node['URI'][1..] || signature_node.parent['ID']
      end

      # Get the ds:Signature element from the document
      # @return [Nokogiri::XML::Element] The Signature element
      def signature_node
        @signature_node ||= noko.at_xpath('//ds:Signature', { 'ds' => RubySaml::XML::DSIG }) ||
                            (raise RubySaml::ValidationError.new('No Signature node found'))
      end

      # Get the ds:SignedInfo element from the document
      # @return [Nokogiri::XML::Element] The SignedInfo element
      def signed_info_node
        signature_node.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::DSIG) ||
          (raise RubySaml::ValidationError.new('No SignedInfo node found'))
      end

      def canon_algorithm
        canon_algorithm_from_transforms || canon_algorithm_from_signed_info
      end

      def canon_algorithm_from_signed_info
        canon_method_node = signed_info_node.at_xpath(
          './ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        RubySaml::XML.canon_algorithm(canon_method_node)
      end

      def canon_algorithm_from_transforms
        transforms = reference_node.xpath('./ds:Transforms/ds:Transform', { 'ds' => RubySaml::XML::DSIG })
        transform_element = transforms.reverse.detect { |el| el['Algorithm'] }
        RubySaml::XML.canon_algorithm(transform_element, default: false)
      end
    end
  end
end

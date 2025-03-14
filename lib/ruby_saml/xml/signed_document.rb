# frozen_string_literal: true

require 'rexml/document'
require 'rexml/security'
require 'rexml/xpath'
require 'ruby_saml/error_handling'
require 'ruby_saml/utils'

REXML::Security.entity_expansion_limit = 0

module RubySaml
  module XML
    class SignedDocument < REXML::Document
      include RubySaml::ErrorHandling

      attr_reader :processed,
                  :referenced_xml

      def initialize(response, errors = [])
        super(response)
        @errors = errors
        reset_elements
      end

      def reset_elements
        @referenced_xml = nil
        @cached_signed_info = nil
        @signature = nil
        @signature_hash_algorithm = nil
        @ref = nil
        @processed = false
      end

      def signed_element_id
        @signed_element_id ||= extract_signed_element_id
      end

      # Validates the referenced_xml, which is the signed part of the document
      def validate_document(idp_cert_fingerprint, soft = true, options = {})
        # get cert from response
        cert_element = REXML::XPath.first(
          self,
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::DSIG }
        )

        if cert_element
          base64_cert = RubySaml::Utils.element_text(cert_element)
          cert_text = Base64.decode64(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue OpenSSL::X509::CertificateError => _e
            return append_error('Document Certificate Error', soft)
          end

          if options[:fingerprint_alg]
            fingerprint_alg = RubySaml::XML.hash_algorithm(options[:fingerprint_alg]).new
          else
            fingerprint_alg = OpenSSL::Digest.new('SHA256')
          end
          fingerprint = fingerprint_alg.hexdigest(cert.to_der)

          # check cert matches registered idp cert
          if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/, '').downcase
            return append_error('Fingerprint mismatch', soft)
          end

          base64_cert = Base64.encode64(cert.to_der)
        elsif options[:cert]
          base64_cert = Base64.encode64(options[:cert].to_pem)
        elsif soft
          return false
        else
          return append_error('Certificate element missing in response (ds:X509Certificate) and not cert provided at settings', soft)
        end

        validate_signature(base64_cert, soft)
      end

      def validate_document_with_cert(idp_cert, soft = true)
        # get cert from response
        cert_element = REXML::XPath.first(
          self,
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::DSIG }
        )

        if cert_element
          base64_cert = RubySaml::Utils.element_text(cert_element)
          cert_text = Base64.decode64(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue OpenSSL::X509::CertificateError => _e
            return append_error('Document Certificate Error', soft)
          end

          # check saml response cert matches provided idp cert
          if idp_cert.to_pem != cert.to_pem
            return append_error('Certificate of the Signature element does not match provided certificate', soft)
          end
        end

        encoded_idp_cert = Base64.encode64(idp_cert.to_pem)
        validate_signature(encoded_idp_cert, true)
      end

      def cache_referenced_xml(soft, check_malformed_doc: true)
        reset_elements
        @processed = true

        begin
          noko = RubySaml::XML.safe_load_nokogiri(self, check_malformed_doc: check_malformed_doc)
        rescue StandardError => e
          @errors << e.message
          return false if soft

          raise ValidationError.new("XML load failed: #{e.message}")
        end

        # get signature node
        sig_element = noko.at_xpath(
          '//ds:Signature',
          { 'ds' => RubySaml::XML::DSIG }
        )
        return if sig_element.nil?

        # signature method
        sig_alg_value = sig_element.at_xpath(
          './ds:SignedInfo/ds:SignatureMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        @signature_hash_algorithm = RubySaml::XML.hash_algorithm(sig_alg_value)

        # get signature
        base64_signature = sig_element.at_xpath(
          './ds:SignatureValue',
          { 'ds' => RubySaml::XML::DSIG }
        )
        return if base64_signature.nil?

        base64_signature_text = base64_signature.content
        @signature = Base64.decode64(base64_signature_text) if base64_signature_text

        # canonicalization method
        canon_method_node = sig_element.at_xpath(
          './ds:SignedInfo/ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        canon_algorithm = RubySaml::XML.canon_algorithm(canon_method_node)

        noko_sig_element = noko.at_xpath('//ds:Signature', 'ds' => RubySaml::XML::DSIG)
        noko_signed_info_element = noko_sig_element.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::DSIG)
        @cached_signed_info = noko_signed_info_element.canonicalize(canon_algorithm)

        # Now get the @referenced_xml to use?
        rexml_signed_info = REXML::Document.new(@cached_signed_info.to_s).root

        noko_sig_element.remove

        # get inclusive namespaces
        inclusive_namespaces = extract_inclusive_namespaces

        # check digests
        @ref = REXML::XPath.first(rexml_signed_info, './ds:Reference', { 'ds' => DSIG })
        return if @ref.nil?

        reference_nodes = noko.xpath('//*[@ID=$id]', nil, { 'id' => extract_signed_element_id })

        hashed_element = reference_nodes[0]
        return if hashed_element.nil?

        canon_method_node = noko_signed_info_element.at_xpath(
          './ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        canon_algorithm = RubySaml::XML.canon_algorithm(canon_method_node)
        canon_algorithm = process_transforms(@ref, canon_algorithm)

        @referenced_xml = hashed_element.canonicalize(canon_algorithm, inclusive_namespaces)
      end

      def validate_signature(base64_cert, soft = true)
        cache_referenced_xml(soft) unless @processed

        return append_error('Cert is missing', soft) if base64_cert.nil?
        return append_error('No Signature Hash Algorithm Method found', soft) if @signature_hash_algorithm.nil?
        return append_error('No Signature node found', soft) if @signature.nil?
        return append_error('No canonized SignedInfo ', soft) if @cached_signed_info.nil?
        return append_error('No Reference node found', soft) if @ref.nil?
        return append_error('No referenced XML', soft) if @referenced_xml.nil?

        # get certificate object
        cert_text = Base64.decode64(base64_cert)
        cert = OpenSSL::X509::Certificate.new(cert_text)

        digest_method_node = REXML::XPath.first(
          @ref,
          './ds:DigestMethod',
          { 'ds' => DSIG }
        )
        digest_algorithm = RubySaml::XML.hash_algorithm(digest_method_node)
        hash = digest_algorithm.digest(@referenced_xml)
        encoded_digest_value = REXML::XPath.first(
          @ref,
          './ds:DigestValue',
          { 'ds' => DSIG }
        )
        encoded_digest_value_text = RubySaml::Utils.element_text(encoded_digest_value)
        digest_value = encoded_digest_value_text.nil? ? nil : Base64.decode64(encoded_digest_value_text)

        # Compare the computed "hash" with the "signed" hash
        unless hash && hash == digest_value
          return append_error('Digest mismatch', soft)
        end

        # verify signature
        signature_verified = false
        begin
          signature_verified = cert.public_key.verify(@signature_hash_algorithm.new, @signature, @cached_signed_info)
        rescue OpenSSL::PKey::PKeyError # rubocop:disable Lint/SuppressedException
        end
        return append_error('Key validation error', soft) unless signature_verified

        true
      end

      private

      def process_transforms(ref, canon_algorithm)
        transforms = REXML::XPath.match(
          ref,
          './ds:Transforms/ds:Transform',
          { 'ds' => RubySaml::XML::DSIG }
        )

        transforms.each do |transform_element|
          next unless transform_element.attributes&.[]('Algorithm')

          canon_algorithm = RubySaml::XML.canon_algorithm(transform_element, default: false)
        end

        canon_algorithm
      end

      def digests_match?(hash, digest_value)
        hash == digest_value
      end

      def extract_signed_element_id
        reference_element = REXML::XPath.first(
          self,
          '//ds:Signature/ds:SignedInfo/ds:Reference',
          { 'ds' => RubySaml::XML::DSIG }
        )

        return nil if reference_element.nil?

        sei = reference_element.attribute('URI').value[1..]
        sei.nil? ? reference_element.parent.parent.parent.attribute('ID').value : sei
      end

      def extract_inclusive_namespaces
        element = REXML::XPath.first(
          self,
          '//ec:InclusiveNamespaces',
          { 'ec' => RubySaml::XML::C14N }
        )
        return unless element

        element.attributes.get_attribute('PrefixList').value.split
      end
    end
  end
end

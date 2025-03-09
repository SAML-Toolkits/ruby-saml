# frozen_string_literal: true

require 'ruby_saml/xml/base_document'
require 'ruby_saml/error_handling'
require 'ruby_saml/utils'

module RubySaml
  module XML
    class SignedDocument < BaseDocument
      include RubySaml::ErrorHandling

      def initialize(response, errors = [])
        super(response)
        @errors = errors
      end

      def signed_element_id
        @signed_element_id ||= extract_signed_element_id
      end

      def validate_document(idp_cert_fingerprint, soft = true, options = {})
        # get cert from response
        cert_element = REXML::XPath.first(
          self,
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
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
            fingerprint_alg = RubySaml::XML::Crypto.hash_algorithm(options[:fingerprint_alg]).new
          else
            fingerprint_alg = OpenSSL::Digest.new('SHA256')
          end
          fingerprint = fingerprint_alg.hexdigest(cert.to_der)

          # check cert matches registered idp cert
          if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,'').downcase
            return append_error('Fingerprint mismatch', soft)
          end
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
          { 'ds' => RubySaml::XML::Crypto::DSIG }
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
        else
          base64_cert = Base64.encode64(idp_cert.to_pem)
        end

        validate_signature(base64_cert, true)
      end

      def validate_signature(base64_cert, soft = true)
        noko = Nokogiri::XML(to_s) do |config|
          config.options = RubySaml::XML::BaseDocument::NOKOGIRI_OPTIONS
        end

        # get signature node
        sig_element = noko.at_xpath(
          '//ds:Signature',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )

        # signature method
        sig_alg_value = sig_element.at_xpath(
          './ds:SignedInfo/ds:SignatureMethod',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )
        signature_hash_algorithm = RubySaml::XML::Crypto.hash_algorithm(sig_alg_value)

        # get signature
        base64_signature = sig_element.at_xpath(
          './ds:SignatureValue',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        ).content
        signature = Base64.decode64(base64_signature)

        # canonicalization method
        canon_method_node = sig_element.at_xpath(
          './ds:SignedInfo/ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )
        canon_algorithm = RubySaml::XML::Crypto.canon_algorithm(canon_method_node)

        noko_sig_element = noko.at_xpath('//ds:Signature', 'ds' => RubySaml::XML::Crypto::DSIG)
        noko_signed_info_element = noko_sig_element.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::Crypto::DSIG)

        canon_string = noko_signed_info_element.canonicalize(canon_algorithm)
        noko_sig_element.remove

        # get signed info
        signed_info_element = sig_element.at_xpath(
          './ds:SignedInfo',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )

        # get inclusive namespaces
        inclusive_namespaces = extract_inclusive_namespaces

        # check digests
        ref = signed_info_element.at_xpath(
          './ds:Reference',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )

        reference_nodes = noko.xpath('//*[@ID=$id]', nil, { 'id' => extract_signed_element_id })

        # ensure no elements with same ID to prevent signature wrapping attack.
        if reference_nodes.length > 1
          return append_error('Digest mismatch. Duplicated ID found', soft)
        end

        hashed_element = reference_nodes[0]

        canon_method_node = signed_info_element.at_xpath(
          './ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )
        canon_algorithm = RubySaml::XML::Crypto.canon_algorithm(canon_method_node)
        canon_algorithm = process_transforms(ref, canon_algorithm)

        canon_hashed_element = hashed_element.canonicalize(canon_algorithm, inclusive_namespaces)

        digest_method_node = ref.at_xpath(
          './ds:DigestMethod',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )
        digest_algorithm = RubySaml::XML::Crypto.hash_algorithm(digest_method_node)

        hash = digest_algorithm.digest(canon_hashed_element)
        encoded_digest_value = ref.at_xpath(
          './ds:DigestValue',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        ).content
        digest_value = Base64.decode64(encoded_digest_value)

        unless digests_match?(hash, digest_value)
          return append_error('Digest mismatch', soft)
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
        return append_error('Key validation error', soft) unless signature_verified

        true
      end

      private

      def process_transforms(ref, canon_algorithm)
        transforms = REXML::XPath.match(
          ref,
          './ds:Transforms/ds:Transform',
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )

        transforms.each do |transform_element|
          next unless transform_element.attributes&.[]('Algorithm')

          canon_algorithm = RubySaml::XML::Crypto.canon_algorithm(transform_element, default: false)
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
          { 'ds' => RubySaml::XML::Crypto::DSIG }
        )

        return nil if reference_element.nil?

        sei = reference_element.attribute('URI').value[1..]
        sei.nil? ? reference_element.parent.parent.parent.attribute('ID').value : sei
      end

      def extract_inclusive_namespaces
        element = REXML::XPath.first(
          self,
          '//ec:InclusiveNamespaces',
          { 'ec' => RubySaml::XML::Crypto::C14N }
        )
        return unless element

        prefix_list = element.attributes.get_attribute('PrefixList').value
        prefix_list.split
      end
    end
  end
end

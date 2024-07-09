# frozen_string_literal: true

require 'ruby_saml/xml/base_document'
require 'ruby_saml/error_handling'
require 'ruby_saml/utils'

module RubySaml
  module XML
    class SignedDocument < BaseDocument
      include RubySaml::ErrorHandling

      attr_writer :signed_element_id

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
          "//ds:X509Certificate",
          { "ds"=>DSIG }
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
            fingerprint_alg = RubySaml::XML::BaseDocument.new.algorithm(options[:fingerprint_alg]).new
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
          { 'ds'=>DSIG }
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
        document = Nokogiri::XML(to_s) do |config|
          config.options = RubySaml::XML::BaseDocument::NOKOGIRI_OPTIONS
        end

        # create a rexml document
        @working_copy ||= REXML::Document.new(to_s).root

        # get signature node
        sig_element = REXML::XPath.first(
            @working_copy,
            '//ds:Signature',
            {'ds'=>DSIG}
          )

        # signature method
        sig_alg_value = REXML::XPath.first(
          sig_element,
          './ds:SignedInfo/ds:SignatureMethod',
          {'ds'=>DSIG}
        )
        signature_algorithm = algorithm(sig_alg_value)

        # get signature
        base64_signature = REXML::XPath.first(
          sig_element,
          './ds:SignatureValue',
          {'ds' => DSIG}
        )
        signature = Base64.decode64(RubySaml::Utils.element_text(base64_signature))

        # canonicalization method
        canon_algorithm = canon_algorithm REXML::XPath.first(
          sig_element,
          './ds:SignedInfo/ds:CanonicalizationMethod',
          'ds' => DSIG
        )

        noko_sig_element = document.at_xpath('//ds:Signature', 'ds' => DSIG)
        noko_signed_info_element = noko_sig_element.at_xpath('./ds:SignedInfo', 'ds' => DSIG)

        canon_string = noko_signed_info_element.canonicalize(canon_algorithm)
        noko_sig_element.remove

        # get inclusive namespaces
        inclusive_namespaces = extract_inclusive_namespaces

        # check digests
        ref = REXML::XPath.first(sig_element, '//ds:Reference', {'ds'=>DSIG})

        hashed_element = document.at_xpath('//*[@ID=$id]', nil, { 'id' => extract_signed_element_id })

        canon_algorithm = canon_algorithm REXML::XPath.first(
          ref,
          '//ds:CanonicalizationMethod',
          { 'ds' => DSIG }
        )

        canon_algorithm = process_transforms(ref, canon_algorithm)

        canon_hashed_element = hashed_element.canonicalize(canon_algorithm, inclusive_namespaces)

        digest_algorithm = algorithm(REXML::XPath.first(
          ref,
          '//ds:DigestMethod',
          { 'ds' => DSIG }
        ))
        hash = digest_algorithm.digest(canon_hashed_element)
        encoded_digest_value = REXML::XPath.first(
          ref,
          '//ds:DigestValue',
          { 'ds' => DSIG }
        )
        digest_value = Base64.decode64(RubySaml::Utils.element_text(encoded_digest_value))

        unless digests_match?(hash, digest_value)
          return append_error('Digest mismatch', soft)
        end

        # get certificate object
        cert_text = Base64.decode64(base64_cert)
        cert = OpenSSL::X509::Certificate.new(cert_text)

        # verify signature
        unless cert.public_key.verify(signature_algorithm.new, signature, canon_string)
          return append_error('Key validation error', soft)
        end

        true
      end

      private

      def process_transforms(ref, canon_algorithm)
        transforms = REXML::XPath.match(
          ref,
          '//ds:Transforms/ds:Transform',
          { 'ds' => DSIG }
        )

        transforms.each do |transform_element|
          next unless transform_element.attributes && transform_element.attributes['Algorithm']

          algorithm = transform_element.attributes['Algorithm']
          case algorithm
          when 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
               'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments'
            canon_algorithm = Nokogiri::XML::XML_C14N_1_0
          when 'http://www.w3.org/2006/12/xml-c14n11',
               'http://www.w3.org/2006/12/xml-c14n11#WithComments'
            canon_algorithm = Nokogiri::XML::XML_C14N_1_1
          when 'http://www.w3.org/2001/10/xml-exc-c14n#',
               'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
            canon_algorithm = Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
          end
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
          {'ds'=>DSIG}
        )

        return nil if reference_element.nil?

        sei = reference_element.attribute('URI').value[1..]
        sei.nil? ? reference_element.parent.parent.parent.attribute('ID').value : sei
      end

      def extract_inclusive_namespaces
        element = REXML::XPath.first(
          self,
          '//ec:InclusiveNamespaces',
          { 'ec' => C14N }
        )
        return unless element

        prefix_list = element.attributes.get_attribute('PrefixList').value
        prefix_list.split
      end
    end
  end
end

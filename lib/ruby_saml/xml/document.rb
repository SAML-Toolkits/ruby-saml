# frozen_string_literal: true

require 'ruby_saml/xml/base_document'

module RubySaml
  module XML
    class Document < BaseDocument
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

      attr_writer :uuid

      def uuid
        @uuid ||= root&.attr('ID')
      end

      # <Signature>
      #   <SignedInfo>
      #     <CanonicalizationMethod />
      #     <SignatureMethod />
      #     <Reference>
      #        <Transforms>
      #        <DigestMethod>
      #        <DigestValue>
      #     </Reference>
      #     <Reference /> etc.
      #   </SignedInfo>
      #   <SignatureValue />
      #   <KeyInfo />
      #   <Object />
      # </Signature>
      def sign_document(private_key, certificate, signature_method = RSA_SHA256, digest_method = SHA256)
        noko = Nokogiri::XML(to_s) do |config|
          config.options = RubySaml::XML::BaseDocument::NOKOGIRI_OPTIONS
        end

        # Create signature elements using Nokogiri
        signature_element = Nokogiri::XML::Element.new('ds:Signature', self)
        signature_element['xmlns:ds'] = RubySaml::XML::Crypto::DSIG

        signed_info_element = Nokogiri::XML::Element.new('ds:SignedInfo', self)
        signature_element.add_child(signed_info_element)

        canon_method_element = Nokogiri::XML::Element.new('ds:CanonicalizationMethod', self)
        canon_method_element['Algorithm'] = RubySaml::XML::Crypto::C14N
        signed_info_element.add_child(canon_method_element)

        sig_method_element = Nokogiri::XML::Element.new('ds:SignatureMethod', self)
        sig_method_element['Algorithm'] = signature_method
        signed_info_element.add_child(sig_method_element)

        # Add Reference
        reference_element = Nokogiri::XML::Element.new('ds:Reference', self)
        reference_element['URI'] = "##{uuid}"
        signed_info_element.add_child(reference_element)

        # Add Transforms
        transforms_element = Nokogiri::XML::Element.new('ds:Transforms', self)
        reference_element.add_child(transforms_element)

        transform1 = Nokogiri::XML::Element.new('ds:Transform', self)
        transform1['Algorithm'] = RubySaml::XML::Crypto::ENVELOPED_SIG
        transforms_element.add_child(transform1)

        transform2 = Nokogiri::XML::Element.new('ds:Transform', self)
        transform2['Algorithm'] = RubySaml::XML::Crypto::C14N
        transforms_element.add_child(transform2)

        inc_namespaces = Nokogiri::XML::Element.new('ec:InclusiveNamespaces', self)
        inc_namespaces['xmlns:ec'] = RubySaml::XML::Crypto::C14N
        inc_namespaces['PrefixList'] = INC_PREFIX_LIST
        transform2.add_child(inc_namespaces)

        digest_method_element = Nokogiri::XML::Element.new('ds:DigestMethod', self)
        digest_method_element['Algorithm'] = digest_method
        reference_element.add_child(digest_method_element)

        inclusive_namespaces = INC_PREFIX_LIST.split
        canon_doc = noko.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N), inclusive_namespaces)

        digest_value_element = Nokogiri::XML::Element.new('ds:DigestValue', self)
        digest_value_element.content = compute_digest(canon_doc, RubySaml::XML::Crypto.hash_algorithm(digest_method_element))
        reference_element.add_child(digest_value_element)

        # add SignatureValue
        noko_sig_element = Nokogiri::XML(signature_element.to_s) do |config|
          config.options = RubySaml::XML::BaseDocument::NOKOGIRI_OPTIONS
        end

        noko_signed_info_element = noko_sig_element.at_xpath('//ds:Signature/ds:SignedInfo', 'ds' => RubySaml::XML::Crypto::DSIG)
        canon_string = noko_signed_info_element.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N))

        signature = compute_signature(private_key, RubySaml::XML::Crypto.hash_algorithm(signature_method).new, canon_string)

        sig_value_element = Nokogiri::XML::Element.new('ds:SignatureValue', self)
        sig_value_element.content = signature
        signature_element.add_child(sig_value_element)

        # add KeyInfo
        key_info_element = Nokogiri::XML::Element.new('ds:KeyInfo', self)
        signature_element.add_child(key_info_element)

        x509_element = Nokogiri::XML::Element.new('ds:X509Data', self)
        key_info_element.add_child(x509_element)

        x509_cert_element = Nokogiri::XML::Element.new('ds:X509Certificate', self)
        x509_element.add_child(x509_cert_element)

        if certificate.is_a?(String)
          certificate = OpenSSL::X509::Certificate.new(certificate)
        end
        x509_cert_element.content = Base64.encode64(certificate.to_der).gsub(/\n/, '')

        # add the signature
        issuer_element = at_xpath('//saml:Issuer')
        if issuer_element
          issuer_element.after(signature_element)
        elsif root.children.any?
          root.children.first.before(signature_element)
        else
          root.add_child(signature_element)
        end
      end

      private

      def compute_signature(private_key, signature_hash_algorithm, document)
        Base64.encode64(private_key.sign(signature_hash_algorithm, document)).gsub(/\n/, '')
      end

      def compute_digest(document, digest_algorithm)
        digest = digest_algorithm.digest(document)
        Base64.encode64(digest).strip
      end
    end
  end
end
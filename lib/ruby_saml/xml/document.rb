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
        @uuid ||= @document.root&.[]('ID')
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
        # Build Signature element
        signature_element = Nokogiri::XML::Node.new('ds:Signature', @document)
        signature_element.add_namespace('ds', RubySaml::XML::Crypto::DSIG)

        # Add SignedInfo
        signed_info_element = Nokogiri::XML::Node.new('ds:SignedInfo', @document)
        signature_element.add_child(signed_info_element)

        # Add CanonicalizationMethod to SignedInfo
        canonicalization_method = Nokogiri::XML::Node.new('ds:CanonicalizationMethod', @document)
        canonicalization_method['Algorithm'] = RubySaml::XML::Crypto::C14N
        signed_info_element.add_child(canonicalization_method)

        # Add SignatureMethod to SignedInfo
        signature_method_node = Nokogiri::XML::Node.new('ds:SignatureMethod', @document)
        signature_method_node['Algorithm'] = signature_method
        signed_info_element.add_child(signature_method_node)

        # Add Reference
        reference_element = Nokogiri::XML::Node.new('ds:Reference', @document)
        reference_element['URI'] = "##{uuid}"
        signed_info_element.add_child(reference_element)

        # Add Transforms to Reference
        transforms_element = Nokogiri::XML::Node.new('ds:Transforms', @document)
        reference_element.add_child(transforms_element)

        # Add Enveloped Sig to Transforms
        enveloped_transform = Nokogiri::XML::Node.new('ds:Transform', @document)
        enveloped_transform['Algorithm'] = RubySaml::XML::Crypto::ENVELOPED_SIG
        transforms_element.add_child(enveloped_transform)

        # Add Canonicalization to Transforms
        c14n_transform = Nokogiri::XML::Node.new('ds:Transform', @document)
        c14n_transform['Algorithm'] = RubySaml::XML::Crypto::C14N
        inclusive_namespaces = Nokogiri::XML::Node.new('ec:InclusiveNamespaces', @document)
        inclusive_namespaces['xmlns:ec'] = RubySaml::XML::Crypto::C14N
        inclusive_namespaces['PrefixList'] = INC_PREFIX_LIST
        c14n_transform.add_child(inclusive_namespaces)
        transforms_element.add_child(c14n_transform)

        # add DigestMethod to Reference
        digest_method_element = Nokogiri::XML::Node.new('ds:DigestMethod', @document)
        digest_method_element['Algorithm'] = digest_method
        reference_element.add_child(digest_method_element)

        # add DigestValue to Reference
        canon_doc = @document.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N), INC_PREFIX_LIST.split)
        digest_value = compute_digest(canon_doc, RubySaml::XML::Crypto.hash_algorithm(digest_method))
        digest_value_element = Nokogiri::XML::Node.new('ds:DigestValue', @document)
        digest_value_element.content = digest_value
        reference_element.add_child(digest_value_element)

        # add SignatureValue to Signature
        signed_info_canon = signed_info_element.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N))
        signature_value = compute_signature(private_key, RubySaml::XML::Crypto.hash_algorithm(signature_method).new, signed_info_canon)
        signature_value_element = Nokogiri::XML::Node.new('ds:SignatureValue', @document)
        signature_value_element.content = signature_value
        signature_element.add_child(signature_value_element)

        # add KeyInfo to Signature
        key_info_element = Nokogiri::XML::Node.new('ds:KeyInfo', @document)
        signature_element.add_child(key_info_element)

        # add X509Data to KeyInfo
        x509_data_element = Nokogiri::XML::Node.new('ds:X509Data', @document)
        key_info_element.add_child(x509_data_element)

        # add X509Certificate to X509Data
        x509_certificate_element = Nokogiri::XML::Node.new('ds:X509Certificate', @document)
        x509_certificate_element.content = Base64.encode64(certificate.to_der).delete("\n")
        x509_data_element.add_child(x509_certificate_element)

        # add Signature to document root
        issuer_element = @document.at_xpath('//saml:Issuer', saml: 'urn:oasis:names:tc:SAML:2.0:assertion')
        if issuer_element
          issuer_element.add_next_sibling(signature_element)
        elsif (first_child = @document.root.children.first)
          first_child.add_previous_sibling(signature_element)
        else
          @document.root.add_child(signature_element)
        end
      end

      private

      def compute_signature(private_key, signature_hash_algorithm, document)
        Base64.encode64(private_key.sign(signature_hash_algorithm, document)).delete("\n")
      end

      def compute_digest(document, digest_algorithm)
        digest = digest_algorithm.digest(document)
        Base64.encode64(digest).strip
      end
    end
  end
end

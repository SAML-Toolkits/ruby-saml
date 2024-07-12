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
        @uuid ||= document.root&.attributes&.[]('ID')
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

        signature_element = REXML::Element.new('ds:Signature').add_namespace('ds', RubySaml::XML::Crypto::DSIG)
        signed_info_element = signature_element.add_element('ds:SignedInfo')
        signed_info_element.add_element('ds:CanonicalizationMethod', {'Algorithm' => RubySaml::XML::Crypto::C14N})
        signed_info_element.add_element('ds:SignatureMethod', {'Algorithm'=>signature_method})

        # Add Reference
        reference_element = signed_info_element.add_element('ds:Reference', {'URI' => "##{uuid}"})

        # Add Transforms
        transforms_element = reference_element.add_element('ds:Transforms')
        transforms_element.add_element('ds:Transform', {'Algorithm' => RubySaml::XML::Crypto::ENVELOPED_SIG})
        c14element = transforms_element.add_element('ds:Transform', {'Algorithm' => RubySaml::XML::Crypto::C14N})
        c14element.add_element('ec:InclusiveNamespaces', {'xmlns:ec' => RubySaml::XML::Crypto::C14N, 'PrefixList' => INC_PREFIX_LIST})

        digest_method_element = reference_element.add_element('ds:DigestMethod', {'Algorithm' => digest_method})
        inclusive_namespaces = INC_PREFIX_LIST.split
        canon_doc = noko.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N), inclusive_namespaces)
        reference_element.add_element('ds:DigestValue').text = compute_digest(canon_doc, RubySaml::XML::Crypto.hash_algorithm(digest_method_element))

        # add SignatureValue
        noko_sig_element = Nokogiri::XML(signature_element.to_s) do |config|
          config.options = RubySaml::XML::BaseDocument::NOKOGIRI_OPTIONS
        end

        noko_signed_info_element = noko_sig_element.at_xpath('//ds:Signature/ds:SignedInfo', 'ds' => RubySaml::XML::Crypto::DSIG)
        canon_string = noko_signed_info_element.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N))

        signature = compute_signature(private_key, RubySaml::XML::Crypto.hash_algorithm(signature_method).new, canon_string)
        signature_element.add_element('ds:SignatureValue').text = signature

        # add KeyInfo
        key_info_element  = signature_element.add_element('ds:KeyInfo')
        x509_element      = key_info_element.add_element('ds:X509Data')
        x509_cert_element = x509_element.add_element('ds:X509Certificate')
        if certificate.is_a?(String)
          certificate = OpenSSL::X509::Certificate.new(certificate)
        end
        x509_cert_element.text = Base64.encode64(certificate.to_der).gsub(/\n/, '')

        # add the signature
        issuer_element = elements['//saml:Issuer']
        if issuer_element
          root.insert_after(issuer_element, signature_element)
        elsif (first_child = root.children[0])
          root.insert_before(first_child, signature_element)
        else
          root.add_element(signature_element)
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

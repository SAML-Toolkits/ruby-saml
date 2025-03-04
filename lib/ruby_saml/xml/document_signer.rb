# frozen_string_literal: true

require 'ruby_saml/xml/base_document'

module RubySaml
  module XML
    module DocumentSigner
      extend self

      INC_PREFIX_LIST = '#default samlp saml ds xs xsi md'

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
      def sign_document(document, private_key, certificate, signature_method = RSA_SHA256, digest_method = SHA256, uuid = nil)
        noko = Nokogiri::XML(document.to_s) do |config|
          config.options = RubySaml::XML::BaseDocument::NOKOGIRI_OPTIONS
        end

        # Use provided uuid or try to get it from the document
        uuid ||= noko.root&.attr('ID')

        # Create signature elements using Nokogiri
        signature_element = Nokogiri::XML::Element.new('ds:Signature', noko)
        signature_element['xmlns:ds'] = RubySaml::XML::Crypto::DSIG

        signed_info_element = Nokogiri::XML::Element.new('ds:SignedInfo', noko)
        signature_element.add_child(signed_info_element)

        canon_method_element = Nokogiri::XML::Element.new('ds:CanonicalizationMethod', noko)
        canon_method_element['Algorithm'] = RubySaml::XML::Crypto::C14N
        signed_info_element.add_child(canon_method_element)

        sig_method_element = Nokogiri::XML::Element.new('ds:SignatureMethod', noko)
        sig_method_element['Algorithm'] = signature_method
        signed_info_element.add_child(sig_method_element)

        # Add Reference
        reference_element = Nokogiri::XML::Element.new('ds:Reference', noko)
        reference_element['URI'] = "##{uuid}"
        signed_info_element.add_child(reference_element)

        # Add Transforms
        transforms_element = Nokogiri::XML::Element.new('ds:Transforms', noko)
        reference_element.add_child(transforms_element)

        transform1 = Nokogiri::XML::Element.new('ds:Transform', noko)
        transform1['Algorithm'] = RubySaml::XML::Crypto::ENVELOPED_SIG
        transforms_element.add_child(transform1)

        transform2 = Nokogiri::XML::Element.new('ds:Transform', noko)
        transform2['Algorithm'] = RubySaml::XML::Crypto::C14N
        transforms_element.add_child(transform2)

        inc_namespaces = Nokogiri::XML::Element.new('ec:InclusiveNamespaces', noko)
        inc_namespaces['xmlns:ec'] = RubySaml::XML::Crypto::C14N
        inc_namespaces['PrefixList'] = INC_PREFIX_LIST
        transform2.add_child(inc_namespaces)

        digest_method_element = Nokogiri::XML::Element.new('ds:DigestMethod', noko)
        digest_method_element['Algorithm'] = digest_method
        reference_element.add_child(digest_method_element)

        inclusive_namespaces = INC_PREFIX_LIST.split
        canon_doc = noko.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N), inclusive_namespaces)

        digest_value_element = Nokogiri::XML::Element.new('ds:DigestValue', noko)
        digest_value_element.content = compute_digest(canon_doc, RubySaml::XML::Crypto.hash_algorithm(digest_method_element))
        reference_element.add_child(digest_value_element)

        # add SignatureValue
        noko_sig_element = Nokogiri::XML(signature_element.to_s) do |config|
          config.options = RubySaml::XML::BaseDocument::NOKOGIRI_OPTIONS
        end

        noko_signed_info_element = noko_sig_element.at_xpath('//ds:Signature/ds:SignedInfo', 'ds' => RubySaml::XML::Crypto::DSIG)
        canon_string = noko_signed_info_element.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N))

        signature = compute_signature(private_key, RubySaml::XML::Crypto.hash_algorithm(signature_method).new, canon_string)

        sig_value_element = Nokogiri::XML::Element.new('ds:SignatureValue', noko)
        sig_value_element.content = signature
        signature_element.add_child(sig_value_element)

        # add KeyInfo
        key_info_element = Nokogiri::XML::Element.new('ds:KeyInfo', noko)
        signature_element.add_child(key_info_element)

        x509_element = Nokogiri::XML::Element.new('ds:X509Data', noko)
        key_info_element.add_child(x509_element)

        x509_cert_element = Nokogiri::XML::Element.new('ds:X509Certificate', noko)
        x509_element.add_child(x509_cert_element)

        if certificate.is_a?(String)
          certificate = OpenSSL::X509::Certificate.new(certificate)
        end
        x509_cert_element.content = Base64.encode64(certificate.to_der).gsub(/\n/, '')

        # add the signature
        issuer_element = noko.at_xpath('//saml:Issuer', 'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion')
        if issuer_element
          issuer_element.after(signature_element)
        elsif noko.root.children.any?
          noko.root.children.first.before(signature_element)
        else
          noko.root.add_child(signature_element)
        end

        noko
      end

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

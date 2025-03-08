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
      def sign_document(private_key, certificate, signature_method = RubySaml::XML::Crypto::RSA_SHA256, digest_method = RubySaml::XML::Crypto::SHA256)
        noko = Nokogiri::XML(to_s) do |config|
          config.options = RubySaml::XML::BaseDocument::NOKOGIRI_OPTIONS
        end

        # Create the signature structure using Builder
        builder = Nokogiri::XML::Builder.new do |xml|
          xml['ds'].Signature('xmlns:ds' => RubySaml::XML::Crypto::DSIG) do
            xml['ds'].SignedInfo do
              xml['ds'].CanonicalizationMethod(Algorithm: RubySaml::XML::Crypto::C14N)
              xml['ds'].SignatureMethod(Algorithm: signature_method)
              xml['ds'].Reference(URI: "##{noko.root.attr('ID')}") do
                xml['ds'].Transforms do
                  xml['ds'].Transform(Algorithm: RubySaml::XML::Crypto::ENVELOPED_SIG)
                  xml['ds'].Transform(Algorithm: RubySaml::XML::Crypto::C14N) do
                    xml['ec'].InclusiveNamespaces(
                      'xmlns:ec' => RubySaml::XML::Crypto::C14N,
                      PrefixList: INC_PREFIX_LIST
                    )
                  end
                end
                xml['ds'].DigestMethod(Algorithm: digest_method)

                # We'll compute and add DigestValue after creating the structure
                xml['ds'].DigestValue
              end
            end

            # We'll add these after the digest computation
            xml['ds'].SignatureValue
            xml['ds'].KeyInfo do
              xml['ds'].X509Data do
                xml['ds'].X509Certificate
              end
            end
          end
        end

        # Extract the signature element from the builder
        signature_element = builder.doc.root

        # Calculate digest
        inclusive_namespaces = INC_PREFIX_LIST.split
        canon_doc = noko.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N), inclusive_namespaces)
        digest_value = compute_digest(canon_doc, RubySaml::XML::Crypto.hash_algorithm(digest_method))

        digest_value_element = signature_element.at_xpath('//ds:DigestValue', 'ds' => RubySaml::XML::Crypto::DSIG)
        digest_value_element.content = digest_value

        # Canonicalize the SignedInfo element for signing
        signed_info_element = signature_element.at_xpath('//ds:SignedInfo', 'ds' => RubySaml::XML::Crypto::DSIG)
        canon_string = signed_info_element.canonicalize(RubySaml::XML::Crypto.canon_algorithm(RubySaml::XML::Crypto::C14N))
        signature = compute_signature(private_key, RubySaml::XML::Crypto.hash_algorithm(signature_method).new, canon_string)

        # Set the signature value
        sig_value_element = signature_element.at_xpath('//ds:SignatureValue', 'ds' => RubySaml::XML::Crypto::DSIG)
        sig_value_element.content = signature

        # Set the certificate
        certificate = OpenSSL::X509::Certificate.new(certificate) if certificate.is_a?(String)
        x509_cert_element = signature_element.at_xpath('//ds:X509Certificate', 'ds' => RubySaml::XML::Crypto::DSIG)
        x509_cert_element.content = Base64.encode64(certificate.to_der).delete("\n")

        # add the signature
        signature_element = convert_nokogiri_to_rexml(signature_element)
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
        Base64.encode64(private_key.sign(signature_hash_algorithm, document)).delete("\n")
      end

      def compute_digest(document, digest_algorithm)
        digest = digest_algorithm.digest(document)
        Base64.encode64(digest).strip
      end

      # TODO: This is a shim method which will be removed when the
      # full Nokogiri conversion is complete
      def convert_nokogiri_to_rexml(noko_element, parent_namespaces = Set.new)
        rexml_element = REXML::Element.new("#{"#{noko_element.namespace.prefix}:" if noko_element.namespace}#{noko_element.name}")

        if noko_element.namespace && !parent_namespaces.include?(noko_element.namespace)
          rexml_element.add_namespace(noko_element.namespace.prefix, noko_element.namespace.href)
        end

        noko_element.attributes.each do |name, value|
          rexml_element.add_attribute(name, value)
        end

        # Copy text content (if any)
        if noko_element.text?
          rexml_element.text = noko_element.text
        end

        # Recursively copy child elements
        noko_element.children.each do |child|
          if child.element?
            rexml_element.add_element(convert_nokogiri_to_rexml(child, parent_namespaces << noko_element.namespace))
          elsif child.text?
            rexml_element.add_text(child.text)
          end
        end

        rexml_element
      end
    end
  end
end

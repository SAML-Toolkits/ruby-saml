# frozen_string_literal: true

require 'rexml/document'
require 'rexml/security'
require 'rexml/xpath'

module RubySaml
  module XML
    class Document < REXML::Document
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
      def sign_document(private_key, certificate, signature_method = RubySaml::XML::RSA_SHA256, digest_method = RubySaml::XML::SHA256)
        signature_element = build_signature_element(private_key, certificate, signature_method, digest_method)
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

      def build_signature_element(private_key, certificate, signature_method, digest_method)
        # Parse the original document
        noko = Nokogiri::XML(to_s) do |config|
          config.options = RubySaml::XML::NOKOGIRI_OPTIONS
        end

        # Build the Signature element
        signature_element = Nokogiri::XML::Builder.new do |xml|
          xml['ds'].Signature('xmlns:ds' => RubySaml::XML::DSIG) do
            xml['ds'].SignedInfo do
              xml['ds'].CanonicalizationMethod(Algorithm: RubySaml::XML::C14N)
              xml['ds'].SignatureMethod(Algorithm: signature_method)
              xml['ds'].Reference(URI: "##{noko.root.attr('ID')}") do
                xml['ds'].Transforms do
                  xml['ds'].Transform(Algorithm: RubySaml::XML::ENVELOPED_SIG)
                  xml['ds'].Transform(Algorithm: RubySaml::XML::C14N) do
                    xml['ec'].InclusiveNamespaces(
                      'xmlns:ec' => RubySaml::XML::C14N,
                      PrefixList: INC_PREFIX_LIST
                    )
                  end
                end
                xml['ds'].DigestMethod(Algorithm: digest_method)
                xml['ds'].DigestValue(digest_value(noko, digest_method))
              end
            end
            xml['ds'].SignatureValue # Value is added below
            xml['ds'].KeyInfo do
              xml['ds'].X509Data do
                xml['ds'].X509Certificate(certificate_value(certificate))
              end
            end
          end
        end.doc.root

        # Set the signature value
        signed_info_element = signature_element.at_xpath('//ds:SignedInfo', 'ds' => RubySaml::XML::DSIG)
        sig_value_element = signature_element.at_xpath('//ds:SignatureValue', 'ds' => RubySaml::XML::DSIG)
        sig_value_element.content = signature_value(signed_info_element, private_key, signature_method)

        signature_element
      end

      def digest_value(document, digest_method)
        inclusive_namespaces = INC_PREFIX_LIST.split
        canon_algorithm = RubySaml::XML.canon_algorithm(RubySaml::XML::C14N)
        hash_algorithm = RubySaml::XML.hash_algorithm(digest_method)

        canon_doc = document.canonicalize(canon_algorithm, inclusive_namespaces)
        Base64.encode64(hash_algorithm.digest(canon_doc)).strip
      end

      def signature_value(signed_info_element, private_key, signature_method)
        canon_algorithm = RubySaml::XML.canon_algorithm(RubySaml::XML::C14N)
        hash_algorithm = RubySaml::XML.hash_algorithm(signature_method).new

        canon_string = signed_info_element.canonicalize(canon_algorithm)
        Base64.encode64(private_key.sign(hash_algorithm, canon_string)).delete("\n")
      end

      def certificate_value(certificate)
        certificate = OpenSSL::X509::Certificate.new(certificate) if certificate.is_a?(String)
        Base64.encode64(certificate.to_der).delete("\n")
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

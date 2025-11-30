# frozen_string_literal: true

module RubySaml
  module XML
    # Given an XML document, returns a copy with an XML Signature element added to it.
    module DocumentSigner
      extend self

      INC_PREFIX_LIST = '#default samlp saml ds xs xsi md'

      # Returns a copy of the document with a signature added.
      #
      # @example The Signature is added following the Issuer node.
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
      def sign_document(document, private_key, certificate, signature_method = RubySaml::XML::RSA_SHA256, digest_method = RubySaml::XML::SHA256)
        begin
          noko = RubySaml::XML.safe_load_xml(document.to_s, check_malformed_doc: true)
        rescue StandardError => e
          raise ValidationError.new("XML load failed: #{e.message}") if e.message != 'Empty document'
        end

        sign_document!(noko, private_key, certificate, signature_method, digest_method)
      end

      # Modifies an existing Nokogiri document to add a signature.
      def sign_document!(noko, private_key, certificate, signature_method = RubySaml::XML::RSA_SHA256, digest_method = RubySaml::XML::SHA256)
        signature_node = build_signature_node(noko, private_key, certificate, signature_method, digest_method)

        if (issuer_node = noko.at_xpath('//saml:Issuer', 'saml' => RubySaml::XML::NS_ASSERTION))
          issuer_node.after(signature_node)
        elsif noko.root.children.any?
          noko.root.children.first.before(signature_node)
        else
          noko.root.add_child(signature_node)
        end

        noko
      end

      private

      def build_signature_node(noko, private_key, certificate, signature_method, digest_method)
        signature_node = Nokogiri::XML::Builder.new do |xml|
          xml['ds'].Signature('xmlns:ds' => RubySaml::XML::DSIG) do
            xml['ds'].SignedInfo do
              xml['ds'].CanonicalizationMethod(Algorithm: RubySaml::XML::C14N)
              xml['ds'].SignatureMethod(Algorithm: signature_method)
              xml['ds'].Reference(URI: "##{noko.root['ID']}") do
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
        signed_info_node = signature_node.at_xpath('//ds:SignedInfo', 'ds' => RubySaml::XML::DSIG)
        signature_value_node = signature_node.at_xpath('//ds:SignatureValue', 'ds' => RubySaml::XML::DSIG)
        signature_value_node.content = signature_value(signed_info_node, private_key, signature_method)

        signature_node
      end

      def digest_value(document, digest_method)
        inclusive_namespaces = INC_PREFIX_LIST.split
        canon_algorithm = RubySaml::XML.canon_algorithm(RubySaml::XML::C14N)
        hash_algorithm = RubySaml::XML.hash_algorithm(digest_method)

        canon_doc = document.canonicalize(canon_algorithm, inclusive_namespaces)
        Base64.strict_encode64(hash_algorithm.digest(canon_doc))
      end

      def signature_value(signed_info_node, private_key, signature_method)
        canon_algorithm = RubySaml::XML.canon_algorithm(RubySaml::XML::C14N)
        hash_algorithm = RubySaml::XML.hash_algorithm(signature_method).new

        canon_string = signed_info_node.canonicalize(canon_algorithm)
        Base64.strict_encode64(private_key.sign(hash_algorithm, canon_string))
      end

      def certificate_value(certificate)
        certificate = OpenSSL::X509::Certificate.new(certificate) if certificate.is_a?(String)
        Base64.strict_encode64(certificate.to_der)
      end
    end
  end
end

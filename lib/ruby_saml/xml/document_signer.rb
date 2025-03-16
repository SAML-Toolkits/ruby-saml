# frozen_string_literal: true

module RubySaml
  module XML
    # Given an XML document, returns a copy with an XML Signature element added to it.
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
      # Returns a copy of the document with a signature added.
      def sign_document(document, private_key, certificate, signature_method = RubySaml::XML::RSA_SHA256, digest_method = RubySaml::XML::SHA256)
        noko = RubySaml::XML.safe_load_nokogiri(document.to_s)

        sign_document!(noko, private_key, certificate, signature_method, digest_method)
      end

      # Modifies an existing Nokogiri document to add a signature.
      def sign_document!(noko, private_key, certificate, signature_method = RubySaml::XML::RSA_SHA256, digest_method = RubySaml::XML::SHA256)
        signature_element = build_signature_element(noko, private_key, certificate, signature_method, digest_method)
        issuer_element = noko.at_xpath('//saml:Issuer', 'saml' => RubySaml::XML::NS_ASSERTION)
        if issuer_element
          issuer_element.after(signature_element)
        elsif noko.root.children.any?
          noko.root.children.first.before(signature_element)
        else
          noko.root.add_child(signature_element)
        end

        noko
      end

      private

      def build_signature_element(noko, private_key, certificate, signature_method, digest_method)
        signature_element = Nokogiri::XML::Builder.new do |xml|
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
        Base64.strict_encode64(hash_algorithm.digest(canon_doc))
      end

      def signature_value(signed_info_element, private_key, signature_method)
        canon_algorithm = RubySaml::XML.canon_algorithm(RubySaml::XML::C14N)
        hash_algorithm = RubySaml::XML.hash_algorithm(signature_method).new

        canon_string = signed_info_element.canonicalize(canon_algorithm)
        Base64.strict_encode64(private_key.sign(hash_algorithm, canon_string))
      end

      def certificate_value(certificate)
        certificate = OpenSSL::X509::Certificate.new(certificate) if certificate.is_a?(String)
        Base64.strict_encode64(certificate.to_der)
      end
    end
  end
end

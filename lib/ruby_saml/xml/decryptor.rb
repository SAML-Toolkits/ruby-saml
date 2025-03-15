# frozen_string_literal: true

require 'ruby_saml/error_handling'
require 'nokogiri'

module RubySaml
  module XML
    # Module for handling document decryption
    module Decryptor
      extend self

      # Generates decrypted document with assertions decrypted
      # @param document [Nokogiri::XML::Document] The encrypted SAML document
      # @param decryption_keys [Array] Array of private keys for decryption
      # @return [Nokogiri::XML::Document] The SAML document with assertions decrypted
      def decrypt_document(document, decryption_keys)
        document_copy = RubySaml::XML.safe_load_nokogiri(document.to_s)
        decrypt_document!(document_copy, decryption_keys)
      end

      # Modifies a SAML document to decrypt its EncryptedAssertion element into an Assertion element.
      # @param document [Nokogiri::XML::Document] The SAML document with the encrypted assertion
      # @param decryption_keys [Array] Array of private keys for decryption
      # @return [Nokogiri::XML::Document] The SAML document with the assertion decrypted
      def decrypt_document!(document, decryption_keys)
        validate_decryption_keys!(decryption_keys)

        response_node = document.at_xpath(
          '/p:Response',
          { 'p' => RubySaml::XML::NS_PROTOCOL }
        )

        encrypted_assertion_node = document.at_xpath(
          '/p:Response/EncryptedAssertion | /p:Response/a:EncryptedAssertion',
          { 'p' => RubySaml::XML::NS_PROTOCOL, 'a' => RubySaml::XML::NS_ASSERTION }
        )

        if encrypted_assertion_node && response_node
          response_node.add_child(decrypt_assertion(encrypted_assertion_node, decryption_keys))
          encrypted_assertion_node.remove
        end

        document
      end

      # Decrypts an EncryptedAssertion element
      # @param encrypted_assertion_node [Nokogiri::XML::Element] The EncryptedAssertion element
      # @param decryption_keys [Array] Array of private keys for decryption
      # @return [Nokogiri::XML::Document] The decrypted EncryptedAssertion element
      def decrypt_assertion(encrypted_assertion_node, decryption_keys)
        decrypt_node(encrypted_assertion_node, %r{(.*</(\w+:)?Assertion>)}m, decryption_keys)
      end

      # Decrypts an EncryptedID element
      # @param encrypted_id_node [Nokogiri::XML::Element] The EncryptedID element
      # @param decryption_keys [Array] Array of private keys for decryption
      # @return [Nokogiri::XML::Document] The decrypted EncrypedtID element
      def decrypt_nameid(encrypted_id_node, decryption_keys)
        decrypt_node(encrypted_id_node, %r{(.*</(\w+:)?NameID>)}m, decryption_keys)
      end

      # Decrypts an EncryptedAttribute element
      # @param encrypted_attribute_node [Nokogiri::XML::Element] The EncryptedAttribute element
      # @param decryption_keys [Array] Array of private keys for decryption
      # @return [Nokogiri::XML::Document] The decrypted EncryptedAttribute element
      def decrypt_attribute(encrypted_attribute_node, decryption_keys)
        decrypt_node(encrypted_attribute_node, %r{(.*</(\w+:)?Attribute>)}m, decryption_keys)
      end

      # Decrypt an element
      # @param encrypted_node [Nokogiri::XML::Element] The encrypted element
      # @param regexp [Regexp] The regular expression to extract the decrypted data
      # @param decryption_keys [Array] Array of private keys for decryption
      # @return [Nokogiri::XML::Document] The decrypted element
      def decrypt_node(encrypted_node, regexp, decryption_keys)
        validate_decryption_keys!(decryption_keys)

        # TODO: Remove this
        encrypted_node = Nokogiri::XML(encrypted_node.to_s).root if encrypted_node.is_a?(REXML::Element)

        node_header = if encrypted_node.name == 'EncryptedAttribute'
                        %(<node xmlns:saml="#{RubySaml::XML::NS_ASSERTION}" xmlns:xsi="#{RubySaml::XML::XSI}">)
                      else
                        %(<node xmlns:saml="#{RubySaml::XML::NS_ASSERTION}">)
                      end

        elem_plaintext = decrypt_node_with_multiple_keys(encrypted_node, decryption_keys)

        # If we get some problematic noise in the plaintext after decrypting.
        # This quick regexp parse will grab only the Element and discard the noise.
        elem_plaintext = elem_plaintext.match(regexp)[0]

        # To avoid namespace errors if saml namespace is not defined
        # create a parent node first with the namespace defined
        elem_plaintext = "#{node_header}#{elem_plaintext}</node>"

        doc = Nokogiri::XML(elem_plaintext)

        if encrypted_node.name == 'EncryptedAttribute'
          doc.root.at_xpath('saml:Attribute', 'saml' => RubySaml::XML::NS_ASSERTION)
        else
          doc.root.children.first
        end
      end

      private

      def validate_decryption_keys!(decryption_keys)
        decryption_keys = Array(decryption_keys)
        if !decryption_keys || decryption_keys.empty?
          # TODO: More generic error?
          raise RubySaml::ValidationError.new('An encrypted element was found, but the Settings does not contain any SP private keys to decrypt it')
        elsif decryption_keys.none?(OpenSSL::PKey::RSA)
          raise RubySaml::ValidationError.new('SP encryption private keys must be OpenSSL::PKey::RSA keys')
        end
      end

      # Obtains the decrypted string from an Encrypted node element in XML,
      # given multiple private keys to try.
      # @param encrypted_node [Nokogirl::XML::Element] The Encrypted element
      # @param decryption_keys [OpenSSL::PKey::RSA | Array<OpenSSL::PKey::RSA>] The SP private key(s)
      # @return [String] The decrypted data
      def decrypt_node_with_multiple_keys(encrypted_node, decryption_keys)
        error = nil
        Array(decryption_keys).each do |key|
          return decrypt_node_with_single_key(encrypted_node, key)
        rescue OpenSSL::PKey::PKeyError => e
          error ||= e
        end

        raise(error) if error
      end

      # Obtains the decrypted string from an Encrypted node element in XML
      # @param encrypted_node [Nokogiri::XML::Element] The Encrypted element
      # @param private_key [OpenSSL::PKey::RSA] The SP private key
      # @return [String] The decrypted data
      def decrypt_node_with_single_key(encrypted_node, private_key)
        encrypt_data = encrypted_node.at_xpath(
          './xenc:EncryptedData',
          { 'xenc' => RubySaml::XML::XENC }
        )
        symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)
        cipher_value = encrypt_data.at_xpath(
          './xenc:CipherData/xenc:CipherValue',
          { 'xenc' => RubySaml::XML::XENC }
        )
        node = Base64.decode64(cipher_value.text)
        encrypt_method = encrypt_data.at_xpath(
          './xenc:EncryptionMethod',
          { 'xenc' => RubySaml::XML::XENC }
        )
        algorithm = encrypt_method['Algorithm']
        retrieve_plaintext(node, symmetric_key, algorithm)
      end

      # Obtains the symmetric key from the EncryptedData element
      # @param encrypt_data [Nokogiri::XML::Element] The EncryptedData element
      # @param private_key [OpenSSL::PKey::RSA] The SP private key
      # @return [String] The symmetric key
      def retrieve_symmetric_key(encrypt_data, private_key)
        key_ref = retrieve_symmetric_key_reference(encrypt_data)

        encrypted_key = encrypt_data.at_xpath(
          "./ds:KeyInfo/xenc:EncryptedKey | ./KeyInfo/xenc:EncryptedKey#{' | //xenc:EncryptedKey[@Id=$id]' if key_ref}",
          { 'ds' => DSIG, 'xenc' => RubySaml::XML::XENC },
          { 'id' => key_ref }.compact
        )

        encrypted_symmetric_key_element = encrypted_key.at_xpath(
          './xenc:CipherData/xenc:CipherValue',
          'xenc' => RubySaml::XML::XENC
        )

        cipher_text = Base64.decode64(encrypted_symmetric_key_element.text)

        encrypt_method = encrypted_key.at_xpath(
          './xenc:EncryptionMethod',
          'xenc' => RubySaml::XML::XENC
        )

        algorithm = encrypt_method['Algorithm']
        retrieve_plaintext(cipher_text, private_key, algorithm)
      end

      def retrieve_symmetric_key_reference(encrypt_data)
        reference = encrypt_data.at_xpath(
          './ds:KeyInfo/ds:RetrievalMethod/@URI',
          { 'ds' => DSIG }
        )
        reference = reference&.value&.delete_prefix('#')
        reference unless reference&.empty?
      end

      # Obtains the deciphered text
      # @param cipher_text [String]   The ciphered text
      # @param symmetric_key [String] The symmetric key used to encrypt the text
      # @param algorithm [String]     The encrypted algorithm
      # @return [String] The deciphered text
      def retrieve_plaintext(cipher_text, symmetric_key, algorithm)
        case algorithm
        when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' then cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' then cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc' then cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
        when 'http://www.w3.org/2009/xmlenc11#aes128-gcm' then auth_cipher = OpenSSL::Cipher.new('aes-128-gcm').decrypt
        when 'http://www.w3.org/2009/xmlenc11#aes192-gcm' then auth_cipher = OpenSSL::Cipher.new('aes-192-gcm').decrypt
        when 'http://www.w3.org/2009/xmlenc11#aes256-gcm' then auth_cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' then rsa = symmetric_key
        when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' then oaep = symmetric_key
        end

        if cipher
          iv_len = cipher.iv_len
          data = cipher_text[iv_len..]
          cipher.padding = 0
          cipher.key = symmetric_key
          cipher.iv = cipher_text[0..iv_len - 1]
          assertion_plaintext = cipher.update(data)
          assertion_plaintext << cipher.final
        elsif auth_cipher
          iv_len = auth_cipher.iv_len
          text_len = cipher_text.length
          tag_len = 16
          data = cipher_text[iv_len..text_len - 1 - tag_len]
          auth_cipher.padding = 0
          auth_cipher.key = symmetric_key
          auth_cipher.iv = cipher_text[0..iv_len - 1]
          auth_cipher.auth_data = ''
          auth_cipher.auth_tag = cipher_text[text_len - tag_len..]
          assertion_plaintext = auth_cipher.update(data)
          assertion_plaintext << auth_cipher.final
        elsif rsa
          rsa.private_decrypt(cipher_text)
        elsif oaep
          oaep.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        else
          cipher_text
        end
      end
    end
  end
end

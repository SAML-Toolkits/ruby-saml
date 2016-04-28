if RUBY_VERSION < '1.9'
  require 'uuid'
else
  require 'securerandom'
end

module OneLogin
  module RubySaml

    # SAML2 Auxiliary class
    #
    class Utils
      @@uuid_generator = UUID.new if RUBY_VERSION < '1.9'

      DSIG      = "http://www.w3.org/2000/09/xmldsig#"
      XENC      = "http://www.w3.org/2001/04/xmlenc#"

      # Return a properly formatted x509 certificate
      #
      # @param cert [String] The original certificate
      # @return [String] The formatted certificate
      #
      def self.format_cert(cert)
        # don't try to format an encoded certificate or if is empty or nil
        return cert if cert.nil? || cert.empty? || cert.match(/\x0d/)

        cert = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
        cert = cert.gsub(/[\n\r\s]/, "")
        cert = cert.scan(/.{1,64}/)
        cert = cert.join("\n")
        "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----"
      end

      # Return a properly formatted private key
      #
      # @param key [String] The original private key
      # @return [String] The formatted private key
      #
      def self.format_private_key(key)
        # don't try to format an encoded private key or if is empty
        return key if key.nil? || key.empty? || key.match(/\x0d/)

        # is this an rsa key?
        rsa_key = key.match("RSA PRIVATE KEY")
        key = key.gsub(/\-{5}\s?(BEGIN|END)( RSA)? PRIVATE KEY\s?\-{5}/, "")
        key = key.gsub(/[\n\r\s]/, "")
        key = key.scan(/.{1,64}/)
        key = key.join("\n")
        key_label = rsa_key ? "RSA PRIVATE KEY" : "PRIVATE KEY"
        "-----BEGIN #{key_label}-----\n#{key}\n-----END #{key_label}-----"
      end

      # Build the Query String signature that will be used in the HTTP-Redirect binding
      # to generate the Signature
      # @param params [Hash] Parameters to build the Query String
      # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
      # @option params [String] :data Base64 encoded SAMLRequest or SAMLResponse
      # @option params [String] :relay_state The RelayState parameter
      # @option params [String] :sig_alg The SigAlg parameter
      # @return [String] The Query String
      #
      def self.build_query(params)
        type, data, relay_state, sig_alg = [:type, :data, :relay_state, :sig_alg].map { |k| params[k]}

        url_string = "#{type}=#{CGI.escape(data)}"
        url_string << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
        url_string << "&SigAlg=#{CGI.escape(sig_alg)}"
      end

      # Validate the Signature parameter sent on the HTTP-Redirect binding
      # @param params [Hash] Parameters to be used in the validation process
      # @option params [OpenSSL::X509::Certificate] cert The Identity provider public certtificate
      # @option params [String] sig_alg The SigAlg parameter
      # @option params [String] signature The Signature parameter (base64 encoded)
      # @option params [String] query_string The full GET Query String to be compared
      # @return [Boolean] True if the Signature is valid, False otherwise
      #
      def self.verify_signature(params)
        cert, sig_alg, signature, query_string = [:cert, :sig_alg, :signature, :query_string].map { |k| params[k]}
        signature_algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
        return cert.public_key.verify(signature_algorithm.new, Base64.decode64(signature), query_string)
      end

      # Build the status error message
      # @param status_code [String] StatusCode value
      # @param status_message [Strig] StatusMessage value
      # @return [String] The status error message
      def self.status_error_msg(error_msg, status_code = nil, status_message = nil)
        unless status_code.nil?
          printable_code = status_code.split(':').last
          error_msg << ', was ' + printable_code
        end

        unless status_message.nil?
          error_msg << ' -> ' + status_message
        end

        error_msg
      end

      # Obtains the decrypted string from an Encrypted node element in XML
      # @param encrypted_node [REXML::Element]     The Encrypted element
      # @param private_key    [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The decrypted data
      def self.decrypt_data(encrypted_node, private_key)
        encrypt_data = REXML::XPath.first(
          encrypted_node,
          "./xenc:EncryptedData",
          { 'xenc' => XENC }
        )
        symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)
        cipher_value = REXML::XPath.first(
          encrypt_data,
          "//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue",
          { 'xenc' => XENC }
        )
        node = Base64.decode64(cipher_value.text)
        encrypt_method = REXML::XPath.first(
          encrypt_data,
          "//xenc:EncryptedData/xenc:EncryptionMethod",
          { 'xenc' => XENC }
        )
        algorithm = encrypt_method.attributes['Algorithm']
        retrieve_plaintext(node, symmetric_key, algorithm)
      end

      # Obtains the symmetric key from the EncryptedData element
      # @param encrypt_data [REXML::Element]     The EncryptedData element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The symmetric key
      def self.retrieve_symmetric_key(encrypt_data, private_key)
        encrypted_key = REXML::XPath.first(
          encrypt_data,
          "//xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey or \
           //xenc:EncryptedKey[@Id=substring-after(//xenc:EncryptedData/ds:KeyInfo/ds:RetrievalMethod/@URI, '#')]",
          { "ds" => DSIG, "xenc" => XENC }
        )
        encrypted_symmetric_key_element = REXML::XPath.first(
          encrypted_key,
          "./xenc:CipherData/xenc:CipherValue",
          { "ds" => DSIG, "xenc" => XENC }
        )
        cipher_text = Base64.decode64(encrypted_symmetric_key_element.text)
        encrypt_method = REXML::XPath.first(
          encrypted_key,
          "./xenc:EncryptionMethod",
          {"ds" => DSIG,  "xenc" => XENC }
        )
        algorithm = encrypt_method.attributes['Algorithm']
        retrieve_plaintext(cipher_text, private_key, algorithm)
      end

      # Obtains the deciphered text
      # @param cipher_text [String]   The ciphered text
      # @param symmetric_key [String] The symetric key used to encrypt the text
      # @param algorithm [String]     The encrypted algorithm
      # @return [String] The deciphered text
      def self.retrieve_plaintext(cipher_text, symmetric_key, algorithm)
        case algorithm
          when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' then cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' then cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc' then cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' then rsa = symmetric_key
          when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' then oaep = symmetric_key
        end

        if cipher
          iv_len = cipher.iv_len
          data = cipher_text[iv_len..-1]
          cipher.padding, cipher.key, cipher.iv = 0, symmetric_key, cipher_text[0..iv_len-1]
          assertion_plaintext = cipher.update(data)
          assertion_plaintext << cipher.final
        elsif rsa
          rsa.private_decrypt(cipher_text)
        elsif oaep
          oaep.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        else
          cipher_text
        end
      end

      def self.uuid
        RUBY_VERSION < '1.9' ? "_#{@@uuid_generator.generate}" : "_#{SecureRandom.uuid}"
      end
    end
  end
end

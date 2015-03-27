module OneLogin
  module RubySaml

    # SAML2 Auxiliary class
    #
    class Utils
      # Return the x509 certificate string formatted
      # @param cert [String] The original certificate 
      # @param heads [Boolean] If true, the formatted certificate will include the
      #                        "BEGIN CERTIFICATE" header and the footer.
      # @return [String] The formatted certificate
      #
      def self.format_cert(cert, heads=true)
        unless cert.empty?
          cert = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
          cert = cert.gsub(/[\n\r\s]/, "")
          cert = cert.scan(/.{1,64}/).join("\n")+"\n"
          if heads
            cert = "-----BEGIN CERTIFICATE-----\n" + cert + "-----END CERTIFICATE-----\n"
          end
        end
        cert
      end

      # Return the private key string formatted
      # @param key [String] The original private key 
      # @param heads [Boolean] If true, the formatted private key will include the
      #                  "BEGIN PRIVATE KEY" or the "BEGIN RSA PRIVATE KEY" header and the footer.
      # @return [String] The formatted certificate
      #
      def self.format_private_key(key, heads=true)
        unless key.empty?
          key = key.delete("\n").delete("\r").delete("\x0D")
          if key.index('-----BEGIN PRIVATE KEY-----') != nil
            key = key.gsub('-----BEGIN PRIVATE KEY-----', '')
            key = key.gsub('-----END PRIVATE KEY-----', '')
            key = key.gsub(' ', '')

            key = key.scan(/.{1,64}/).join("\n")+"\n"
            if heads
              key = "-----BEGIN PRIVATE KEY-----\n" + key + "-----END PRIVATE KEY-----\n"
            end
          else
            key = key.gsub('-----BEGIN RSA PRIVATE KEY-----', '')
            key = key.gsub('-----END RSA PRIVATE KEY-----', '')
            key = key.gsub(' ', '')
            key = key.scan(/.{1,64}/).join("\n")+"\n"
            if heads
              key = "-----BEGIN RSA PRIVATE KEY-----\n" + key + "-----END RSA PRIVATE KEY-----\n"
            end
          end
        end
        key
      end

      # Build the Query String signature that will be used in the HTTP-Redirect binding
      # to generate the Signature
      # @param type        [String] 'SAMLRequest' or 'SAMLResponse'
      # @param data        [String] The plain text request or response
      # @param relay_state [String] The RelayState parameter
      # @param sig_alg     [String] The SigAlg parameter                  
      # @return [String] The Query String 
      #
      def self.build_query(type, data, relay_state, sig_alg)
        url_string          = "#{type}=#{CGI.escape(data)}"
        url_string         << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
        url_string         << "&SigAlg=#{CGI.escape(sig_alg)}"          
      end

      # Validate the Signature parameter sent on the HTTP-Redirect binding
      # @param cert         [OpenSSL::X509::Certificate] The Identity provider public certtificate
      # @param sig_alg      [String] The SigAlg parameter
      # @param signature    [String] The Base64 decoded Signature
      # @param query_string [String] The SigAlg parameter
      # @return [Boolean] True if the Signature is valid, False otherwise
      #
      def self.verify_signature(cert, sig_alg, signature, query_string)
        signature_algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
        return cert.public_key.verify(signature_algorithm.new, signature, query_string)        
      end
    end
  end
end
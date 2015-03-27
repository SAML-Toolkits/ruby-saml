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
        if cert && !cert.empty?
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
        if key && !key.empty?
          key = key.delete("\n\r\x0D")
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
      # @param params [Hash] Parameters to build the Query String
      # @option params [String] :type        'SAMLRequest' or 'SAMLResponse'
      # @option params [String] :data        The plain text request or response
      # @option params [String] :relay_state The RelayState parameter
      # @option params [String] :sig_alg     The SigAlg parameter                  
      # @return [String] The Query String 
      #
      def self.build_query(params)
        type, data, relay_state, sig_alg = [:type, :data, :relay_state, :sig_alg].map { |k| params[k]}

        url_string          = "#{type}=#{CGI.escape(data)}"
        url_string         << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
        url_string         << "&SigAlg=#{CGI.escape(sig_alg)}"
      end

      # Validate the Signature parameter sent on the HTTP-Redirect binding
      # @param params [Hash] Parameters to be used in the validation process
      # @option params [OpenSSL::X509::Certificate] cert The Identity provider public certtificate
      # @option params [String] sig_alg      The SigAlg parameter
      # @option params [String] signature    The Base64 decoded Signature
      # @option params [String] query_string The SigAlg parameter
      # @return [Boolean] True if the Signature is valid, False otherwise
      #
      def self.verify_signature(params)
        cert, sig_alg, signature, query_string = [:cert, :sig_alg, :signature, :query_string].map { |k| params[k]}

        signature_algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
        return cert.public_key.verify(signature_algorithm.new, signature, query_string)        
      end
    end
  end
end
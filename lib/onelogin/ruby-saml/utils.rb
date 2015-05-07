module OneLogin
  module RubySaml

    # SAML2 Auxiliary class
    #    
    class Utils
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
    end
  end
end

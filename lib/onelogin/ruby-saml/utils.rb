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
          key = key.delete!("\n\r\x0D")
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

    end
  end
end
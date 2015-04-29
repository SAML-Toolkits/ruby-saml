module OneLogin
  module RubySaml
    class Utils
      # Return a properly formatted x509 certificate
      #
      # @param cert [String] The original certificate
      # @return [String] The formatted certificate
      def self.format_cert(cert)
        # don't try to format an encoded certificate
        return cert if cert.match(/\x0d/)

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
      def self.format_private_key(key)
        # don't try to format an encoded certificate
        return key if key.match(/\x0d/)

        # is this an rsa key?
        rsa_key = key.match("RSA PRIVATE KEY")

        key = key.gsub(/\-{5}\s?(BEGIN|END)( RSA)? PRIVATE KEY\s?\-{5}/, "")
        key = key.gsub(/[\n\r\s]/, "")
        key = key.scan(/.{1,64}/)
        key = key.join("\n")

        key_label = rsa_key ? "RSA PRIVATE KEY" : "PRIVATE KEY"

        "-----BEGIN #{key_label}-----\n#{key}\n-----END #{key_label}-----"
      end
    end
  end
end

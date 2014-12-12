module OneLogin
  module RubySaml
    class Utils
      def self.format_cert(cert)
        # don't try to format an encoded certificate
        return cert if cert.match(/\x0d/)

        cert = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
        cert = cert.gsub(/[\n\r\s]/, "")
        cert = cert.scan(/.{1,64}/)
        cert = cert.join("\n")

        "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----"
      end

      def self.format_private_key(key, heads=true)
        key = key.delete("\n").delete("\r").delete("\x0D")
        if key
          if key.index('-----BEGIN PRIVATE KEY-----') != nil
            key = key.gsub('-----BEGIN PRIVATE KEY-----', '')
            key = key.gsub('-----END PRIVATE KEY-----', '')
            key = key.gsub(' ', '')
            if heads
              key = key.scan(/.{1,64}/).join("\n")+"\n"
              key = "-----BEGIN PRIVATE KEY-----\n" + key + "-----END PRIVATE KEY-----\n"
            end
          else
            key = key.gsub('-----BEGIN RSA PRIVATE KEY-----', '')
            key = key.gsub('-----END RSA PRIVATE KEY-----', '')
            key = key.gsub(' ', '')
            if heads
              key = key.scan(/.{1,64}/).join("\n")+"\n"
              key = "-----BEGIN RSA PRIVATE KEY-----\n" + key + "-----END RSA PRIVATE KEY-----\n"
            end
          end
        end
      end

    end
  end
end

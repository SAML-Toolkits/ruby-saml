module OneLogin
  module RubySaml
    class Utils
      def self.format_cert(cert, heads=true)
        if cert
          cert = cert.delete("\n").delete("\r").delete("\x0D")
          cert = cert.gsub('-----BEGIN CERTIFICATE-----', '')
          cert = cert.gsub('-----END CERTIFICATE-----', '')
          cert = cert.gsub(' ', '')

          if heads
            cert = cert.scan(/.{1,64}/).join("\n")+"\n"
            cert = "-----BEGIN CERTIFICATE-----\n" + cert + "-----END CERTIFICATE-----\n"
          end
        end
        cert
      end

      def self.format_private_key(key, heads=true)
        if key
          key = key.delete("\n").delete("\r").delete("\x0D")
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
        key
      end
    end
  end
end
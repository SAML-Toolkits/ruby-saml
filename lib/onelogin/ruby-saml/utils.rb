module OneLogin
  module RubySaml
    class Utils
      def self.format_cert(cert, heads=true)
        cert = cert.delete("\n").delete("\r").delete("\x0D")
        if cert
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
      # Given a REXML::Element instance, return the concatenation of all child text nodes. Assumes
      # that there all children other than text nodes can be ignored (e.g. comments). If nil is
      # passed, nil will be returned.
      def self.element_text(element)
        element.texts.join if element
      end
    end
  end
end
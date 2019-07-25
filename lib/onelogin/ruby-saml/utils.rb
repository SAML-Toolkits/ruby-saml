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

      # Given a REXML::Element instance, return the concatenation of all child text nodes. Assumes
      # that there all children other than text nodes can be ignored (e.g. comments). If nil is
      # passed, nil will be returned.
      def self.element_text(element)
        element.texts.map(&:value).join if element
      end

      # Return a properly formatted x509 certificate
      #
      # @param cert [String] The original certificate
      # @return [String] The formatted certificate
      #
      def self.format_cert(cert)
        # don't try to format an encoded certificate or if is empty or nil
        if cert.respond_to?(:ascii_only?)
          return cert if cert.nil? || cert.empty? || !cert.ascii_only?
        else
          return cert if cert.nil? || cert.empty? || cert.match(/\x0d/)
        end

        if cert.scan(/BEGIN CERTIFICATE/).length > 1
            formatted_cert = []
          cert.scan(/-{5}BEGIN CERTIFICATE-{5}[\n\r]?.*?-{5}END CERTIFICATE-{5}[\n\r]?/m) {|c|
            formatted_cert << format_cert(c)
          }
          formatted_cert.join("\n")
        else
          cert = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
          cert = cert.gsub(/\r/, "")
          cert = cert.gsub(/\n/, "")
          cert = cert.gsub(/\s/, "")
          cert = cert.scan(/.{1,64}/)
          cert = cert.join("\n")
          "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----"
        end
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
        key = key.gsub(/\n/, "")
        key = key.gsub(/\r/, "")
        key = key.gsub(/\s/, "")
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

      def self.uuid
        RUBY_VERSION < '1.9' ? "_#{@@uuid_generator.generate}" : "_#{SecureRandom.uuid}"
      end
    end
  end
end

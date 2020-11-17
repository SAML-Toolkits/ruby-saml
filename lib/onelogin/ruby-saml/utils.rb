if RUBY_VERSION < '1.9'
  require 'uuid'
else
  require 'securerandom'
end

require "base64"
require "zlib"

module OneLogin
  module RubySaml

    # SAML2 Auxiliary class
    #
    class Utils
      @@uuid_generator = UUID.new if RUBY_VERSION < '1.9'

      BASE64_FORMAT = %r(\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z)

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

      # Build the status error message
      # @param status_code [String] StatusCode value
      # @param status_message [Strig] StatusMessage value
      # @return [String] The status error message
      def self.status_error_msg(error_msg, raw_status_code = nil, status_message = nil)
        unless raw_status_code.nil?
          if raw_status_code.include? "|"
            status_codes = raw_status_code.split(' | ')
            values = status_codes.collect do |status_code|
              status_code.split(':').last
            end
            printable_code = values.join(" => ")
          else
            printable_code = raw_status_code.split(':').last
          end
          error_msg << ', was ' + printable_code
        end

        unless status_message.nil?
          error_msg << ' -> ' + status_message
        end

        error_msg
      end

      # Base64 decode and try also to inflate a SAML Message
      # @param saml [String] The deflated and encoded SAML Message
      # @return [String] The plain SAML Message
      #
      def self.decode_raw_saml(saml)
        return saml unless base64_encoded?(saml)

        decoded = decode(saml)
        begin
          inflate(decoded)
        rescue
          decoded
        end
      end

      # Base 64 decode method
      # @param string [String] The string message
      # @return [String] The decoded string
      #
      def self.decode(string)
        Base64.decode64(string)
      end

      # Base 64 encode method
      # @param string [String] The string
      # @return [String] The encoded string
      #
      def self.encode(string)
        if Base64.respond_to?('strict_encode64')
          Base64.strict_encode64(string)
        else
          Base64.encode64(string).gsub(/\n/, "")
        end
      end

      # Check if a string is base64 encoded
      # @param string [String] string to check the encoding of
      # @return [true, false] whether or not the string is base64 encoded
      #
      def self.base64_encoded?(string)
        !!string.gsub(/[\r\n]|\\r|\\n|\s/, "").match(BASE64_FORMAT)
      end

      # Inflate method
      # @param deflated [String] The string
      # @return [String] The inflated string
      #
      def self.inflate(deflated)
        Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(deflated)
      end

      # Deflate method
      # @param inflated [String] The string
      # @return [String] The deflated string
      #
      def self.deflate(inflated)
        Zlib::Deflate.deflate(inflated, 9)[2..-5]
      end

      # Given two strings, attempt to match them as URIs using Rails' parse method.  If they can be parsed,
      # then the fully-qualified domain name and the host should performa a case-insensitive match, per the
      # RFC for URIs.  If Rails can not parse the string in to URL pieces, return a boolean match of the
      # two strings.  This maintains the previous functionality.
      # @return [Boolean]
      def self.uri_match?(destination_url, settings_url)
        dest_uri = URI.parse(destination_url)
        acs_uri = URI.parse(settings_url)

        if dest_uri.scheme.nil? || acs_uri.scheme.nil? || dest_uri.host.nil? || acs_uri.host.nil?
          raise URI::InvalidURIError
        else
          dest_uri.scheme.downcase == acs_uri.scheme.downcase &&
            dest_uri.host.downcase == acs_uri.host.downcase &&
            dest_uri.path == acs_uri.path &&
            dest_uri.query == acs_uri.query
        end
      rescue URI::InvalidURIError
        original_uri_match?(destination_url, settings_url)
      end

      # If Rails' URI.parse can't match to valid URL, default back to the original matching service.
      # @return [Boolean]
      def self.original_uri_match?(destination_url, settings_url)
        destination_url == settings_url
      end

    end
  end
end

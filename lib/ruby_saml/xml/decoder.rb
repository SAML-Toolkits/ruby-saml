# frozen_string_literal: true

module RubySaml
  module XML
    # Module for handling base64 and deflate encoding.
    module Decoder
      extend self

      DEFAULT_MAX_BYTESIZE = 250_000
      BASE64_FORMAT = %r{\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z}

      # Base64 decode and try also to inflate a SAML Message
      # @param message [String] The deflated and encoded SAML Message
      # @param max_bytesize [Integer] The maximum allowed size of the SAML Message,
      #   to prevent a possible DoS attack.
      # @return [String] The plain SAML Message
      def decode_message(message, max_bytesize = nil)
        return message unless base64_encoded?(message)

        max_bytesize ||= DEFAULT_MAX_BYTESIZE

        if message.bytesize > max_bytesize # rubocop:disable Style/IfUnlessModifier
          raise ValidationError.new("Encoded SAML Message exceeds #{max_bytesize} bytes, so was rejected")
        end

        message = try_inflate(base64_decode(message))

        if message.bytesize > max_bytesize # rubocop:disable Style/IfUnlessModifier
          raise ValidationError.new("SAML Message exceeds #{max_bytesize} bytes, so was rejected")
        end

        message
      end

      # Deflate, base64 encode and url-encode a SAML Message. Used in the HTTP-redirect binding.
      # @param message [String] The plain SAML Message
      # @option :compress [true|false] Whether or not the SAML message should be deflated.
      # @return [String] The deflated and encoded SAML Message (encoded if the compression is requested)
      def encode_message(message, compress: false)
        message = deflate(message) if compress
        base64_encode(message)
      end

      private

      # Base 64 decode method.
      # @param string [String] The string message
      # @return [String] The decoded string
      def base64_decode(string)
        Base64.decode64(string)
      end

      # Base 64 encode method.
      # @param string [String] The string
      # @return [String] The encoded string
      def base64_encode(string)
        Base64.strict_encode64(string)
      end

      # Check if a string is base64 encoded.
      # @param string [String] string to check the encoding of
      # @return [true, false] whether or not the string is base64 encoded
      def base64_encoded?(string)
        string.gsub(/[\s\r\n]|\\r|\\n/, '').match?(BASE64_FORMAT)
      end

      # Attempt inflating a string, if it fails, return the original string.
      # @param data [String] The string
      # @return [String] The inflated or original string
      def try_inflate(data)
        inflate(data)
      rescue Zlib::Error
        data
      end

      # Inflate method.
      # @param deflated [String] The string
      # @return [String] The inflated string
      def inflate(deflated)
        Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(deflated)
      end

      # Deflate method.
      # @param inflated [String] The string
      # @return [String] The deflated string
      def deflate(inflated)
        Zlib::Deflate.deflate(inflated, Zlib::BEST_COMPRESSION)[2..-5]
      end
    end
  end
end

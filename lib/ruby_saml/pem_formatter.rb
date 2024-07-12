# frozen_string_literal: true

module RubySaml
  # Formats PEM-encoded X.509 certificates and private keys to canonical
  # RFC 7468 PEM format, including 64-char lines and BEGIN/END headers.
  #
  # @api private
  module PemFormatter
    extend self

    # Formats X.509 certificate(s) to an array of strings in canonical
    # RFC 7468 PEM format.
    #
    # @param certs [String|Array<String>] String(s) containing
    #   unformatted certificate(s).
    # @return [Array<String>] The formatted certificate(s).
    def format_cert_array(certs)
      format_pem_array(certs, 'CERTIFICATE')
    end

    # Formats one or multiple X.509 certificate(s) to canonical
    # RFC 7468 PEM format.
    #
    # @param cert [String] A string containing unformatted certificate(s).
    # @param multi [true|false] Whether to return multiple certificates
    #   delimited by newline. Default false.
    # @return [String] The formatted certificate(s). Returns nil if the
    #   input is blank.
    def format_cert(cert, multi: false)
      pem_array_to_string(format_cert_array(cert), multi: multi)
    end

    # Formats private keys(s) to canonical RFC 7468 PEM format.
    #
    # @param keys [String|Array<String>] String(s) containing unformatted
    #   private keys(s).
    # @return [Array<String>] The formatted private keys(s).
    def format_private_key_array(keys)
      format_pem_array(keys, 'PRIVATE KEY', %w[RSA ECDSA EC DSA])
    end

    # Formats one or multiple private key(s) to canonical RFC 7468
    # PEM format.
    #
    # @param key [String] A string containing unformatted private keys(s).
    # @param multi [true|false] Whether to return multiple keys
    #   delimited by newline. Default false.
    # @return [String|nil] The formatted private key(s). Returns
    #   nil if the input is blank.
    def format_private_key(key, multi: false)
      pem_array_to_string(format_private_key_array(key), multi: multi)
    end

    private

    def format_pem_array(str, label, known_prefixes = nil)
      return [] unless str

      # Normalize array input using '?' char as a delimiter
      str = str.is_a?(Array) ? str.map { |s| encode_utf8(s) }.join('?') : encode_utf8(str)
      str.strip!
      return [] if str.empty?

      # Find and format PEMs matching the desired label
      pems = str.scan(pem_scan_regexp(label)).map { |pem| format_pem(pem, label, known_prefixes) }

      # If no PEMs matched, remove non-matching PEMs then format the remaining string
      if pems.empty?
        str.gsub!(pem_scan_regexp, '')
        str.strip!
        pems = format_pem(str, label, known_prefixes).scan(pem_scan_regexp(label)) unless str.empty?
      end

      pems
    end

    def pem_array_to_string(pems, multi: false)
      return if pems.empty?
      return pems unless pems.is_a?(Array)

      multi ? pems.join("\n") : pems.first
    end

    # Given a PEM, a label such as "PRIVATE KEY", and a list of known prefixes
    # such as "RSA", "DSA", etc., returns the formatted PEM preserving the known
    # prefix if possible.
    def format_pem(pem, label, known_prefixes = nil)
      prefix = detect_label_prefix(pem, label, known_prefixes)
      label = "#{prefix} #{label}" if prefix
      "-----BEGIN #{label}-----\n#{format_pem_body(pem)}\n-----END #{label}-----"
    end

    # Given a PEM, a label such as "PRIVATE KEY", and a list of known prefixes
    # such as "RSA", "DSA", etc., detects and returns the known prefix if it exists.
    def detect_label_prefix(pem, label, known_prefixes)
      return unless known_prefixes && !known_prefixes.empty?

      pem.match(/(#{Array(known_prefixes).join('|')})\s+#{label.gsub(' ', '\s+')}/)&.[](1)
    end

    # Given a PEM, strips all whitespace and the BEGIN/END lines,
    # then splits the body into 64-character lines.
    def format_pem_body(pem)
      pem.gsub(/\s|#{pem_scan_header}/, '').scan(/.{1,64}/).join("\n")
    end

    # Returns a regexp which can be used to loosely match unformatted PEM(s) in a string.
    def pem_scan_regexp(label = nil)
      base64 = '[A-Za-z\d+/\s]*[A-Za-z\d+]+[A-Za-z\d+/\s]*=?\s*=?\s*'
      /#{pem_scan_header('BEGIN', label)}#{base64}#{pem_scan_header('END', label)}/m
    end

    # Returns a regexp component string to match PEM headers.
    def pem_scan_header(marker = nil, label = nil)
      marker ||= '(BEGIN|END)'
      label ||= '[A-Z\d]+'
      "-{5}\\s*#{marker}\\s(?:[A-Z\\d\\s]*\\s)?#{label.gsub(' ', '\s+')}\\s*-{5}"
    end

    # Encode to UTF-8 using '?' as a delimiter so that non-ASCII chars
    # appearing inside a PEM will cause the PEM to be considered invalid.
    def encode_utf8(str)
      str.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
    end
  end
end

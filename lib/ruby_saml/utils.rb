# frozen_string_literal: true

require 'securerandom'
require 'openssl'
require 'ruby_saml/pem_formatter'

module RubySaml

  # SAML2 Auxiliary class
  #
  module Utils
    extend self

    BINDINGS = { post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                 redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" }.freeze
    DSIG = "http://www.w3.org/2000/09/xmldsig#"
    XENC = "http://www.w3.org/2001/04/xmlenc#"
    DURATION_FORMAT = /^
      (-?)P                       # 1: Duration sign
      (?:
        (?:(\d+)Y)?               # 2: Years
        (?:(\d+)M)?               # 3: Months
        (?:(\d+)D)?               # 4: Days
        (?:T
          (?:(\d+)H)?             # 5: Hours
          (?:(\d+)M)?             # 6: Minutes
          (?:(\d+(?:[.,]\d+)?)S)? # 7: Seconds
        )?
        |
        (\d+)W                    # 8: Weeks
      )
    $/x
    UUID_PREFIX = +'_'

    # Checks if the x509 cert provided is expired.
    #
    # @param cert [OpenSSL::X509::Certificate|String] The x509 certificate.
    # @return [true|false] Whether the certificate is expired.
    def is_cert_expired(cert)
      cert = build_cert_object(cert) if cert.is_a?(String)
      cert.not_after < Time.now
    end

    # Checks if the x509 cert provided has both started and has not expired.
    #
    # @param cert [OpenSSL::X509::Certificate|String] The x509 certificate.
    # @return [true|false] Whether the certificate is currently active.
    def is_cert_active(cert)
      cert = build_cert_object(cert) if cert.is_a?(String)
      now = Time.now
      cert.not_before <= now && cert.not_after >= now
    end

    # Interprets a ISO8601 duration value relative to a given timestamp.
    #
    # @param duration [String] The duration, as a string.
    # @param timestamp [Integer] The unix timestamp we should apply the
    #                            duration to. Optional, default to the
    #                            current time.
    #
    # @return [Integer] The new timestamp, after the duration is applied.
    #
    def parse_duration(duration, timestamp=Time.now.utc)
      matches = duration.match(DURATION_FORMAT)

      if matches.nil?
        raise StandardError.new("Invalid ISO 8601 duration")
      end

      sign = matches[1] == '-' ? -1 : 1

      durYears, durMonths, durDays, durHours, durMinutes, durSeconds, durWeeks =
        matches[2..8].map do |match|
          if match
            match = match.tr(',', '.').gsub(/\.0*\z/, '')
            sign * (match.include?('.') ? match.to_f : match.to_i)
          else
            0
          end
        end

      datetime = Time.at(timestamp).utc.to_datetime
      datetime = datetime.next_year(durYears)
      datetime = datetime.next_month(durMonths)
      datetime = datetime.next_day((7*durWeeks) + durDays)
      datetime.to_time.utc.to_i + (durHours * 3600) + (durMinutes * 60) + durSeconds
    end

    # Formats one or multiple X.509 certificate(s) to canonical RFC 7468 PEM format.
    #
    # @note Unlike `PemFormatter#format_cert`, this method returns the original
    # input string if the input cannot be parsed.
    #
    # @param cert [String] The original certificate(s).
    # @param multi [true|false] Whether to return multiple keys delimited by newline.
    #   Default true for compatibility with legacy behavior (i.e. to parse cert chains).
    # @return [String] The formatted certificate(s). For legacy compatibility reasons,
    #   this method returns the original string if the input cannot be parsed.
    def format_cert(cert, multi: true)
      PemFormatter.format_cert(cert, multi: multi) || cert
    end

    # Formats one or multiple private key(s) to canonical RFC 7468 PEM format.
    #
    # @note Unlike `PemFormatter#format_private_key`, this method returns the
    # original input string if the input cannot be parsed.
    #
    # @param key [String] The original private key(s)
    # @param multi [true|false] Whether to return multiple keys delimited by newline.
    #   Default false for compatibility with legacy behavior.
    # @return [String] The formatted private key(s). For legacy compatibility reasons,
    #   this method returns the original string if the input cannot be parsed.
    def format_private_key(key, multi: false)
      PemFormatter.format_private_key(key, multi: multi) || key
    end

    # Given a certificate string, return an OpenSSL::X509::Certificate object.
    #
    # @param pem [String] The original certificate
    # @return [OpenSSL::X509::Certificate] The certificate object
    def build_cert_object(pem)
      return unless (pem = PemFormatter.format_cert(pem, multi: false))

      OpenSSL::X509::Certificate.new(pem)
    end

    # Given a private key string, return an OpenSSL::PKey::PKey object.
    #
    # @param pem [String] The original private key.
    # @return [OpenSSL::PKey::PKey] The private key object.
    def build_private_key_object(pem)
      return unless (pem = PemFormatter.format_private_key(pem, multi: false))

      error = nil
      private_key_classes(pem).each do |key_class|
        return key_class.new(pem)
      rescue OpenSSL::PKey::PKeyError => e
        error ||= e
      end

      raise error
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
    def build_query(params)
      type, data, relay_state, sig_alg = params.values_at(:type, :data, :relay_state, :sig_alg)

      url_string = +"#{type}=#{CGI.escape(data)}"
      url_string << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
      url_string << "&SigAlg=#{CGI.escape(sig_alg)}"
    end

    # Reconstruct a canonical query string from raw URI-encoded parts, to be used in verifying a signature
    #
    # @param params [Hash] Parameters to build the Query String
    # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
    # @option params [String] :raw_data URI-encoded, base64 encoded SAMLRequest or SAMLResponse, as sent by IDP
    # @option params [String] :raw_relay_state URI-encoded RelayState parameter, as sent by IDP
    # @option params [String] :raw_sig_alg URI-encoded SigAlg parameter, as sent by IDP
    # @return [String] The Query String
    #
    def build_query_from_raw_parts(params)
      type, raw_data, raw_relay_state, raw_sig_alg = params.values_at(:type, :raw_data, :raw_relay_state, :raw_sig_alg)

      url_string = +"#{type}=#{raw_data}"
      url_string << "&RelayState=#{raw_relay_state}" if raw_relay_state
      url_string << "&SigAlg=#{raw_sig_alg}"
    end

    # Prepare raw GET parameters (build them from normal parameters
    # if not provided).
    #
    # @param rawparams [Hash] Raw GET Parameters
    # @param params [Hash] GET Parameters
    # @param lowercase_url_encoding [bool] Lowercase URL Encoding  (For ADFS urlencode compatiblity)
    # @return [Hash] New raw parameters
    #
    def prepare_raw_get_params(rawparams, params, lowercase_url_encoding=false)
      rawparams ||= {}

      if rawparams['SAMLRequest'].nil? && !params['SAMLRequest'].nil?
        rawparams['SAMLRequest'] = escape_request_param(params['SAMLRequest'], lowercase_url_encoding)
      end
      if rawparams['SAMLResponse'].nil? && !params['SAMLResponse'].nil?
        rawparams['SAMLResponse'] = escape_request_param(params['SAMLResponse'], lowercase_url_encoding)
      end
      if rawparams['RelayState'].nil? && !params['RelayState'].nil?
        rawparams['RelayState'] = escape_request_param(params['RelayState'], lowercase_url_encoding)
      end
      if rawparams['SigAlg'].nil? && !params['SigAlg'].nil?
        rawparams['SigAlg'] = escape_request_param(params['SigAlg'], lowercase_url_encoding)
      end

      rawparams
    end

    def escape_request_param(param, lowercase_url_encoding)
      CGI.escape(param).tap do |escaped|
        next unless lowercase_url_encoding

        escaped.gsub!(/%[A-Fa-f0-9]{2}/, &:downcase)
      end
    end

    # Validate the Signature parameter sent on the HTTP-Redirect binding
    # @param params [Hash] Parameters to be used in the validation process
    # @option params [OpenSSL::X509::Certificate] cert The IDP public certificate
    # @option params [String] sig_alg The SigAlg parameter
    # @option params [String] signature The Signature parameter (base64 encoded)
    # @option params [String] query_string The full GET Query String to be compared
    # @return [Boolean] True if the Signature is valid, False otherwise
    #
    def verify_signature(params)
      cert, sig_alg, signature, query_string = params.values_at(:cert, :sig_alg, :signature, :query_string)
      signature_algorithm = RubySaml::XML::Crypto.hash_algorithm(sig_alg)
      cert.public_key.verify(signature_algorithm.new, Base64.decode64(signature), query_string)
    end

    # Build the status error message
    # @param status_code [String] StatusCode value
    # @param status_message [Strig] StatusMessage value
    # @return [String] The status error message
    def status_error_msg(error_msg, raw_status_code = nil, status_message = nil)
      unless raw_status_code.nil?
        if raw_status_code.include?("|")
          status_codes = raw_status_code.split(' | ')
          values = status_codes.collect do |status_code|
            status_code.split(':').last
          end
          printable_code = values.join(" => ")
        else
          printable_code = raw_status_code.split(':').last
        end
        error_msg += ", was #{printable_code}"
      end

      error_msg += " -> #{status_message}" unless status_message.nil?

      error_msg
    end

    # Obtains the decrypted string from an Encrypted node element in XML,
    # given multiple private keys to try.
    # @param encrypted_node [Nokogiri::XML::Node] The Encrypted element
    # @param private_keys [Array<OpenSSL::PKey::RSA>] The SP private key
    # @return [String] The decrypted data
    def decrypt_multi(encrypted_node, private_keys)
      raise ArgumentError.new('private_keys must be specified') if !private_keys || private_keys.empty?

      if private_keys.none?(OpenSSL::PKey::RSA)
        raise ArgumentError.new('private_keys must be OpenSSL::PKey::RSA keys')
      end

      error = nil
      private_keys.each do |key|
        return decrypt_data(encrypted_node, key)
      rescue OpenSSL::PKey::PKeyError => e
        error ||= e
      end

      raise(error) if error
    end

    # Obtains the decrypted string from an Encrypted node element in XML
    # @param encrypted_node [Nokogiri::XML::Node] The Encrypted element
    # @param private_key [OpenSSL::PKey::RSA] The SP private key
    # @return [String] The decrypted data
    def decrypt_data(encrypted_node, private_key)
      encrypt_data = encrypted_node.at_xpath(".//xenc:EncryptedData", xenc: XENC)
      symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)
      cipher_value = encrypt_data.at_xpath(".//xenc:CipherData/xenc:CipherValue", xenc: XENC)
      node = Base64.decode64(cipher_value.content)
      encrypt_method = encrypt_data.at_xpath(".//xenc:EncryptionMethod", xenc: XENC)
      algorithm = encrypt_method['Algorithm']
      retrieve_plaintext(node, symmetric_key, algorithm)
    end

    # Obtains the symmetric key from the EncryptedData element
    # @param encrypt_data [Nokogiri::XML::Node] The EncryptedData element
    # @param private_key [OpenSSL::PKey::RSA] The SP private key
    # @return [String] The symmetric key
    def retrieve_symmetric_key(encrypt_data, private_key)
      encrypted_key = encrypt_data.at_xpath(
        "./ds:KeyInfo/xenc:EncryptedKey | ./KeyInfo/xenc:EncryptedKey | //xenc:EncryptedKey[@Id='#{retrieve_symmetric_key_reference(encrypt_data)}']",
        ds: DSIG, xenc: XENC
      )

      encrypted_symmetric_key_element = encrypted_key.at_xpath(".//xenc:CipherData/xenc:CipherValue", xenc: XENC)

      cipher_text = Base64.decode64(element_text(encrypted_symmetric_key_element))

      encrypt_method = encrypted_key.at_xpath(".//xenc:EncryptionMethod", xenc: XENC)
      algorithm = encrypt_method['Algorithm']

      retrieve_plaintext(cipher_text, private_key, algorithm)
    end

    # Retrieves the symmetric key reference
    # @param encrypt_data [Nokogiri::XML::Node] The EncryptedData element
    # @return [String] The key reference ID
    def retrieve_symmetric_key_reference(encrypt_data)
      retrieval_method = encrypt_data.at_xpath(".//ds:KeyInfo/ds:RetrievalMethod", ds: DSIG)
      retrieval_method&.[]('URI')&.delete_prefix('#')
    end

    # Obtains the deciphered text
    # @param cipher_text [String]   The ciphered text
    # @param symmetric_key [String] The symmetric key used to encrypt the text
    # @param algorithm [String]     The encrypted algorithm
    # @return [String] The deciphered text
    def retrieve_plaintext(cipher_text, symmetric_key, algorithm)
      case algorithm
      when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' then cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
      when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' then cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
      when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc' then cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
      when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
      when 'http://www.w3.org/2009/xmlenc11#aes128-gcm' then auth_cipher = OpenSSL::Cipher.new('aes-128-gcm').decrypt
      when 'http://www.w3.org/2009/xmlenc11#aes192-gcm' then auth_cipher = OpenSSL::Cipher.new('aes-192-gcm').decrypt
      when 'http://www.w3.org/2009/xmlenc11#aes256-gcm' then auth_cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
      when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' then rsa = symmetric_key
      when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' then oaep = symmetric_key
      end

      if cipher
        iv_len = cipher.iv_len
        data = cipher_text[iv_len..]
        cipher.padding = 0
        cipher.key = symmetric_key
        cipher.iv = cipher_text[0..iv_len-1]
        assertion_plaintext = cipher.update(data)
        assertion_plaintext << cipher.final
      elsif auth_cipher
        iv_len = auth_cipher.iv_len
        text_len = cipher_text.length
        tag_len = 16
        data = cipher_text[iv_len..text_len-1-tag_len]
        auth_cipher.padding = 0
        auth_cipher.key = symmetric_key
        auth_cipher.iv = cipher_text[0..iv_len-1]
        auth_cipher.auth_data = ''
        auth_cipher.auth_tag = cipher_text[text_len-tag_len..]
        assertion_plaintext = auth_cipher.update(data)
        assertion_plaintext << auth_cipher.final
      elsif rsa
        rsa.private_decrypt(cipher_text)
      elsif oaep
        oaep.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      else
        cipher_text
      end
    end

    def set_prefix(value)
      UUID_PREFIX.replace value
    end

    def uuid
      "#{UUID_PREFIX}#{SecureRandom.uuid}"
    end

    # Given two strings, attempt to match them as URIs using Rails' parse method.  If they can be parsed,
    # then the fully-qualified domain name and the host should performa a case-insensitive match, per the
    # RFC for URIs.  If Rails can not parse the string in to URL pieces, return a boolean match of the
    # two strings.  This maintains the previous functionality.
    # @return [Boolean]
    def uri_match?(destination_url, settings_url)
      dest_uri = URI.parse(destination_url)
      acs_uri = URI.parse(settings_url)

      if dest_uri.scheme.nil? || acs_uri.scheme.nil? || dest_uri.host.nil? || acs_uri.host.nil?
        raise URI::InvalidURIError
      end

      dest_uri.scheme.casecmp(acs_uri.scheme) == 0 &&
        dest_uri.host.casecmp(acs_uri.host) == 0 &&
        dest_uri.path == acs_uri.path &&
        dest_uri.query == acs_uri.query
    rescue URI::InvalidURIError
      original_uri_match?(destination_url, settings_url)
    end

    # If Rails' URI.parse can't match to valid URL, default back to the original matching service.
    # @return [Boolean]
    def original_uri_match?(destination_url, settings_url)
      destination_url == settings_url
    end

    # Given a Nokogiri::XML::Node instance, return the concatenation of all direct child text nodes.
    # Assumes that all children other than text nodes can be ignored (e.g. comments).
    # If nil is passed, nil will be returned.
    def element_text(element)
      return nil unless element

      element.children.filter_map(&:text).join
    end

    # Given a private key PEM string, return an array of OpenSSL::PKey::PKey classes
    # that can be used to parse it, with the most likely match first.
    def private_key_classes(pem)
      priority = case pem.match(/(RSA|ECDSA|EC|DSA) PRIVATE KEY/)&.[](1)
                 when 'RSA' then OpenSSL::PKey::RSA
                 when 'DSA' then OpenSSL::PKey::DSA
                 when 'ECDSA', 'EC' then OpenSSL::PKey::EC
                 end
      Array(priority) | [OpenSSL::PKey::RSA, OpenSSL::PKey::DSA, OpenSSL::PKey::EC]
    end
  end
end

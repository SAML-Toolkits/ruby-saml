require "xml_security"
require "time"
require "nokogiri"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    class Response < SamlMessage
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      DSIG      = "http://www.w3.org/2000/09/xmldsig#"
      XENC      = "http://www.w3.org/2001/04/xmlenc#" 

      # TODO: This should probably be ctor initialized too... WDYT?
      attr_accessor :settings
      attr_accessor :errors

      attr_reader :options
      attr_reader :response
      attr_reader :document
      attr_reader :original_document

      def initialize(response, options = {})
        @errors = []
        raise ArgumentError.new("Response cannot be nil") if response.nil?
        @options  = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response, @errors)

        # Marshal at Ruby 1.8.7 throw an Exception
        if RUBY_VERSION < "1.9"
          @original_document = XMLSecurity::SignedDocument.new(@response, @errors)
        else
          @original_document = Marshal.load(Marshal.dump(@document))
        end
      end

      def is_valid?
        validate
      end

      def validate!
        validate(false)
      end

      def errors
        @errors
      end

      # The value of the user identifier as designated by the initialization request response
      def name_id
        @name_id ||= begin
          node = xpath_first_from_signed_assertion('/saml:Subject/saml:NameID')
          node.nil? ? nil : node.text
        end
      end

      def sessionindex
        @sessionindex ||= begin
          node = xpath_first_from_signed_assertion('/saml:AuthnStatement')
          node.nil? ? nil : node.attributes['SessionIndex']
        end
      end

      # Returns OneLogin::RubySaml::Attributes enumerable collection.
      # All attributes can be iterated over +attributes.each+ or returned as array by +attributes.all+
      #
      # For backwards compatibility ruby-saml returns by default only the first value for a given attribute with
      #    attributes['name']
      # To get all of the attributes, use:
      #    attributes.multi('name')
      # Or turn off the compatibility:
      #    OneLogin::RubySaml::Attributes.single_value_compatibility = false
      # Now this will return an array:
      #    attributes['name']
      def attributes
        @attr_statements ||= begin
          attributes = Attributes.new

          stmt_element = xpath_first_from_signed_assertion('/saml:AttributeStatement')
          return attributes if stmt_element.nil?

          stmt_element.elements.each do |attr_element|
            name  = attr_element.attributes["Name"]
            values = attr_element.elements.collect{|e|
              # SAMLCore requires that nil AttributeValues MUST contain xsi:nil XML attribute set to "true" or "1"
              # otherwise the value is to be regarded as empty.
              ["true", "1"].include?(e.attributes['xsi:nil']) ? nil : e.text.to_s
            }

            attributes.add(name, values)
          end

          attributes
        end
      end

      # When this user session should expire at latest
      def session_expires_at
        @expires_at ||= begin
          node = xpath_first_from_signed_assertion('/saml:AuthnStatement')
          parse_time(node, "SessionNotOnOrAfter")
        end
      end

      # Checks the status of the response for a "Success" code
      def success?
        @status_code ||= begin
          node = REXML::XPath.first(document, "/samlp:Response/samlp:Status/samlp:StatusCode", { "samlp" => PROTOCOL })
          node.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
        end
      end

      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(document, "/samlp:Response/samlp:Status/samlp:StatusMessage", { "samlp" => PROTOCOL })
          node.text if node
        end
      end

      # Conditions (if any) for the assertion to run
      def conditions
        @conditions ||= xpath_first_from_signed_assertion('/saml:Conditions')
      end

      def not_before
        @not_before ||= parse_time(conditions, "NotBefore")
      end

      def not_on_or_after
        @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(assertion_document, "/samlp:Response/saml:Issuer", { "samlp" => PROTOCOL, "saml" => ASSERTION })
          node ||= xpath_first_from_signed_assertion('/saml:Issuer')
          node.nil? ? nil : node.text
        end
      end

      private

      def validate(soft = true)
        valid_saml?(document, soft)   &&
        validate_response_state(soft) &&
        validate_conditions(soft)     &&
        validate_issuer(soft)         &&
        # If signature on message or non-encrypted assertion, validate_the original document
        # otherwise send to validate the document once the assertion was unencrypted
        validate_right_document(get_fingerprint, soft) &&
        validate_success_status(soft)
      end

      def validate_success_status(soft = true)
        if success?
          true
        else
          soft ? false : validation_error(status_message)
        end
      end

      def validate_structure(soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml-schema-protocol-2.0.xsd'))
          @xml = Nokogiri::XML(self.document.to_s)
        end
        if soft
          @schema.validate(@xml).map{
            @errors << "Schema validation failed";
            return false
          }
        else
          @schema.validate(@xml).map{ |error| @errors << "#{error.message}\n\n#{@xml.to_s}";
            validation_error("#{error.message}\n\n#{@xml.to_s}")
          }
        end
      end

      def validate_response_state(soft = true)
        if response.empty?
          return soft ? false : validation_error("Blank response")
        end

        if settings.nil?
          return soft ? false : validation_error("No settings on response")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def xpath_first_from_signed_assertion(subelt=nil)
        node = REXML::XPath.first(assertion_document, "/samlp:Response/saml:Assertion[@ID='#{assertion_document.signed_element_id}']#{subelt}", { "samlp" => PROTOCOL, "saml" => ASSERTION, 'ds' => DSIG })
        node ||= REXML::XPath.first(assertion_document, "/samlp:Response[@ID='#{assertion_document.signed_element_id}']/saml:Assertion#{subelt}", { "samlp" => PROTOCOL, "saml" => ASSERTION, 'ds' => DSIG })
        node
      end

      def get_fingerprint
        if settings.idp_cert
          cert = OpenSSL::X509::Certificate.new(settings.idp_cert)
          Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
        else
          settings.idp_cert_fingerprint
        end
      end

      def validate_conditions(soft = true)
        return true if conditions.nil?
        return true if options[:skip_conditions]

        now = Time.now.utc

        if not_before && (now + (options[:allowed_clock_drift] || 0)) < not_before
          @errors << "Current time is earlier than NotBefore condition #{(now + (options[:allowed_clock_drift] || 0))} < #{not_before})"
          return soft ? false : validation_error("Current time is earlier than NotBefore condition")
        end

        if not_on_or_after && now >= not_on_or_after
          @errors << "Current time is on or after NotOnOrAfter condition (#{now} >= #{not_on_or_after})"
          return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
        end

        true
      end

      def validate_issuer(soft = true)
        return true if settings.idp_entity_id.nil?

        unless URI.parse(issuer) == URI.parse(settings.idp_entity_id)
          return soft ? false : validation_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
        end
        true
      end

      def parse_time(node, attribute)
        if node && node.attributes[attribute]
          Time.parse(node.attributes[attribute])
        end
      end

      def validate_right_document(get_fingerprint, soft)
        if REXML::XPath.first(document, "/samlp:Response/ds:Signature", { "samlp" => PROTOCOL, "ds" => DSIG })
          original_document.validate_document(get_fingerprint, soft)
        else
          decrypted_response.validate_document(get_fingerprint, soft)
        end
      end

      def decrypted_response
        @decrypted_response ||= assertion_document
      end

      def decrypt_assertion_document
        @encrypted = true
        encrypted_assertion = REXML::XPath.first(document, "(/samlp:Response/EncryptedAssertion/)|(/samlp:Response/saml:EncryptedAssertion/)", { "samlp" => PROTOCOL, "saml" => ASSERTION, 'ds' => DSIG })
        cipher_data = REXML::XPath.first(encrypted_assertion, "./xenc:EncryptedData", { 'xenc' => XENC })
        aes_key = retrieve_symmetric_key(cipher_data)
        cipher_value = REXML::XPath.first(cipher_data, "./xenc:CipherData/xenc:CipherValue", { 'xenc' => XENC })
        encrypted_assertion = Base64.decode64(cipher_value.text)
        enc_method = REXML::XPath.first(cipher_data, "./xenc:EncryptionMethod", { 'xenc' => XENC })
        algorithm = enc_method.attributes['Algorithm']
        assertion_plaintext = retrieve_plaintext(encrypted_assertion, aes_key, algorithm)
        REXML::Document.new(assertion_plaintext)
      end

      def assertion_document
        @assertion_document ||= begin
          if encrypted_element = REXML::XPath.first(document, "(/samlp:Response/EncryptedAssertion/)|(/samlp:Response/saml:EncryptedAssertion/)", { "samlp" => PROTOCOL, "saml" => ASSERTION })
            response = REXML::XPath.first(document, "/samlp:Response/", { "samlp" => PROTOCOL })
            response.add(decrypt_assertion_document)
            encrypted_element.remove
            XMLSecurity::SignedDocument.new(document.to_s)
          else
            document
          end
        end
      end

      def retrieve_symmetric_key(cipher_data)
        private_key = OpenSSL::PKey::RSA.new(settings.private_key)
        encrypted_aes_key_element = REXML::XPath.first(cipher_data, "./ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", { "ds" => DSIG, "xenc" => XENC })
        encrypted_aes_key = Base64.decode64(encrypted_aes_key_element.text)
        private_key.private_decrypt(encrypted_aes_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      end

      def retrieve_plaintext(cipher_text, key, algorithm)
        case algorithm
        when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' then cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' then cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc' then cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' then rsa = key
        when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' then oaep = key
        end

        if cipher
          iv = cipher_text[0..15]
          data = cipher_text[16..-1]
          cipher.padding, cipher.key, cipher.iv = 0, key, iv
          assertion_plaintext = cipher.update(data)
          assertion_plaintext << cipher.final
          # We get some problematic noise in the plaintext after decrypting.
          # This quick regexp parse will grab only the assertion and discard the noise.
          assertion_plaintext.match(/(.*<\/(saml:|)Assertion>)/m)[0]
        elsif rsa
          rsa.private_decrypt(cipher_text)
        elsif oaep
          oaep.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        else
          cipher_text
        end
      end
    end
  end
end

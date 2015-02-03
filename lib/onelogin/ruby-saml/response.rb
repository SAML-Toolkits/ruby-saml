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

      # TODO: This should probably be ctor initialized too... WDYT?
      attr_accessor :settings
      attr_accessor :errors

      attr_reader :options
      attr_reader :response
      attr_reader :document

      def initialize(response, options = {})
        @errors = []
        raise ArgumentError.new("Response cannot be nil") if response.nil?
        @options  = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response, @errors)
      end

      def is_valid?
        validate
      end

      def validate!(soft=false, response_id = nil)
        validate(soft, response_id)
      end

      def errors
        @errors
      end

      # The value of the user identifier as designated by the initialization request response
      def name_id
        @name_id ||= begin
          node = xpath_first_from_signed_assertion('/a:Subject/a:NameID')
          node.nil? ? nil : node.text
        end
      end

      def sessionindex
        @sessionindex ||= begin
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
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

          stmt_element = xpath_first_from_signed_assertion('/a:AttributeStatement')
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
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
          node.nil? ? nil : parse_time(node, "SessionNotOnOrAfter")
        end
      end

      # Checks the status of the response for a "Success" code
      def success?
        not status_code.nil? and status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
      end

      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.attributes["Value"] if node and not node.attributes.nil?
        end
      end

      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusMessage", { "p" => PROTOCOL, "a" => ASSERTION })
          node.text if node
        end
      end

      # Conditions (if any) for the assertion to run
      def conditions
        @conditions ||= xpath_first_from_signed_assertion('/a:Conditions')
      end

      def not_before
        @not_before ||= parse_time(conditions, "NotBefore")
      end

      def not_on_or_after
        @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
      end

      def issuers
        @issuers ||= begin
          issuers = []
          node = REXML::XPath.first(document, "/p:Response/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          if node
            issuers << node.text
          end

          node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          if node
            issuers << node.text          
          end

          issuers.uniq
        end
      end

      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      def destination
        @destination ||= begin
          node = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes['Destination']
        end
      end

      def audiences
        @audiences ||= begin
          audiences = []
          nodes = xpath_from_signed_assertion('/a:Conditions/a:AudienceRestriction/a:Audience')
          nodes.each do |node|
            unless node.nil? or node.text.empty?
              audiences << node.text
            end
          end
          audiences
        end
     end

     def current_url
      @current_url ||= begin
        settings.assertion_consumer_service_url
      end
     end

      private

      def validate(soft = true, request_id = nil)
        @errors = []
        validate_response_state(soft) &&
        validate_id                   &&
        validate_version              &&
        validate_success_status(soft) &&
        validate_num_assertion        &&
        validate_no_encrypted_attributes(soft)    &&
        validate_signed_elements()    &&
        validate_structure(soft)      &&
        validate_in_response_to(request_id, soft) &&
        validate_conditions(soft)     &&
        validate_destination(soft)    &&
        validate_audience(soft)       &&
        validate_issuer(soft)         &&
        validate_session_expiration(soft) &&
        validate_subject_confirmation(soft) &&
        document.validate_document(get_fingerprint, soft)
      end

      def validate_response_state(soft = true)
        if response.nil? or response.empty?
          @errors << "Blank SAML Response"
          return soft ? false : validation_error("Blank SAML Response")
        end

        if settings.nil?
          @errors << "No settings on SAML Response"
          return soft ? false : validation_error("No settings on SAML Response")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          @errors << "No fingerprint or certificate on settings"
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def validate_id()
        unless id(document)
          @errors << "Missing ID attribute on SAML Response"
          return false
        end
        true
      end

      def validate_version()
        unless version(document) == "2.0"
          @errors << "Unsupported SAML version"
          return false
        end
        true
      end

      def validate_num_assertion()
        assertions = REXML::XPath.match(document, "//a:Assertion", { "a" => ASSERTION })
        encrypted_assertions = REXML::XPath.match(document, "//a:EncryptedAssertion", { "a" => ASSERTION })

        unless assertions.length + encrypted_assertions.length == 1
          @errors << "SAML Response must contain 1 assertion"
          return false
        end
        true
      end

      def validate_success_status(soft = true)
        if success?
          true
        else
          error_msg = 'The status code of the Response was not Success'
          unless status_code.nil?
            printable_code = status_code.split(':').pop
            error_msg +=  ', was ' + printable_code
          end

          unless status_message.nil?
            error_msg +=  ' -> ' + status_message
          end

          @errors << error_msg
          soft ? false : validation_error(error_msg)
        end
      end

      def validate_signed_elements()
        signature_nodes = REXML::XPath.match(@document, "//ds:Signature", {"ds"=>DSIG})

        signed_elements = []
        signature_nodes.each do |signature_node|
          signed_element = signature_node.parent.name
          if signed_element != 'Response' and signed_element != 'Assertion'
            @errors << "Found an unexpected Signature Element. SAML Response rejected"
            return false
          end
          signed_elements << signed_element
        end

        unless signature_nodes.length < 3 and not signed_elements.empty?
          @errors << "Found an unexpected number of Signature Element. SAML Response rejected"
          return false
        end

        true
      end

      def validate_structure(soft = true)
        valid = valid_saml?(@document, soft)
        unless valid
          @errors << "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd"
        end
        valid
      end

      def validate_in_response_to(request_id = nil, soft = true)
        return true if request_id.nil? or self.in_response_to.nil? or self.in_response_to.empty?

        unless request_id != self.in_response_to
          return true
        end

        error_msg = "The InResponseTo of the Response: #{self.in_response_to}, does not match the ID of the AuthNRequest sent by the SP: #{request_id}"
        @errors << error_msg
        return soft ? false : validation_error(error_msg)
      end

      def validate_no_encrypted_attributes(soft = true)
        nodes = REXML::XPath.match(@document, "/p:Response/a:Assertion/a:AttributeStatement/a:EncryptedAttribute" , { "p" => PROTOCOL, "a" => ASSERTION })
        if nodes and nodes.length > 0
          @errors << "There is an EncryptedAttribute in the Response and this SP not support them"
          return soft ? false : validation_error("There is an EncryptedAttribute in the Response and this SP not support them")
        end
        true
      end

      # TODO Replace settings.assertion_consumer_service_url by the right current_url
      def validate_destination(soft = true)
        return true if self.destination.nil? or self.destination.empty? or settings.assertion_consumer_service_url.nil? or settings.assertion_consumer_service_url.empty?

        unless self.destination == current_url
          error_msg = "The response was received at #{self.destination} instead of #{current_url}"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        true
      end

      def validate_audience(soft = true)
        return true if self.audiences.empty? or settings.issuer.nil? or settings.issuer.empty?

        unless self.audiences.include? settings.issuer
          error_msg = "#{self.settings.issuer} is not a valid audience for this Response"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        true
      end

      def xpath_first_from_signed_assertion(subelt=nil)
        node = REXML::XPath.first(
            document,
            "/p:Response/a:Assertion[@ID=$id]#{subelt}",
            { "p" => PROTOCOL, "a" => ASSERTION },
            { 'id' => document.signed_element_id }
        )
        node ||= REXML::XPath.first(
            document,
            "/p:Response[@ID=$id]/a:Assertion#{subelt}",
            { "p" => PROTOCOL, "a" => ASSERTION },
            { 'id' => document.signed_element_id }
        )
        node
      end

      def xpath_from_signed_assertion(subelt=nil)
        node = REXML::XPath.match(
            document,
            "/p:Response/a:Assertion[@ID=$id]#{subelt}",
            { "p" => PROTOCOL, "a" => ASSERTION },
            { 'id' => document.signed_element_id }
        )
        node.concat( REXML::XPath.match(
            document,
            "/p:Response[@ID=$id]/a:Assertion#{subelt}",
            { "p" => PROTOCOL, "a" => ASSERTION },
            { 'id' => document.signed_element_id }
        ))
        node
      end

      def get_fingerprint
        settings.idp_cert_fingerprint || begin
          if settings.idp_cert
            certificate = OneLogin::RubySaml::Utils.format_cert(settings.idp_cert)
            x509 = OpenSSL::X509::Certificate.new(certificate)
            Digest::SHA1.hexdigest(x509.to_der).upcase.scan(/../).join(":")
          end
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

        issuers.each do |issuer|
          unless URI.parse(issuer) == URI.parse(settings.idp_entity_id)
            error_msg = "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>"
            @errors << error_msg
            return soft ? false : validation_error(error_msg)
          end
        end

        true
      end

      def validate_session_expiration(soft = true)
        return true if session_expires_at.nil?

        now = Time.now.utc
        unless session_expires_at > now
          error_msg = "The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        true
      end

      def validate_subject_confirmation(soft = true)
        valid_subject_confirmation = false

        subject_confirmation_nodes = xpath_from_signed_assertion('/a:Subject/a:SubjectConfirmation')
        
        now = Time.now.utc
        subject_confirmation_nodes.each do |subject_confirmation|
          if subject_confirmation.attributes.include? "Method" and subject_confirmation.attributes['Method'] != 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
            next
          end

          confirmation_data_node = REXML::XPath.first(subject_confirmation, 'a:SubjectConfirmationData', { "a" => ASSERTION })

          if not confirmation_data_node
            next
          else
            if confirmation_data_node.attributes.include? "InResponseTo" and confirmation_data_node.attributes['InResponseTo'] != in_response_to
              next
            end

            if confirmation_data_node.attributes.include? "Recipient" and confirmation_data_node.attributes['Recipient'] != current_url
              next
            end

            if confirmation_data_node.attributes.include? "NotOnOrAfter" and parse_time(confirmation_data_node, "NotOnOrAfter") <= now
              next
            end

            if confirmation_data_node.attributes.include? "NotBefore" and parse_time(confirmation_data_node, "NotBefore") > now
              next
            end
            
            valid_subject_confirmation = true
            break
          end
        end

        if not valid_subject_confirmation
          error_msg = "A valid SubjectConfirmation was not found on this Response"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end

        true
      end

      def parse_time(node, attribute)
        if node && node.attributes[attribute]
          Time.parse(node.attributes[attribute])
        end
      end

    end
  end
end

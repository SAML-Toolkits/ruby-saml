require 'zlib'
require 'time'
require 'nokogiri'

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML 2 Logout Request (SLO IdP initiated, Parser)
    #
    class SloLogoutrequest < SamlMessage

      # OneLogin::RubySaml::Settings  Toolkit settings
      attr_accessor :settings

      # Array with the causes
      attr_accessor :errors

      attr_reader :options
      attr_reader :request
      attr_reader :document

      # Constructs the Logout Request. A Logout Request Object that is an extension of the SamlMessage class.
      # @param [String] A UUEncoded Logout Request from the IdP.
      # @param [Hash]   Settings. Some options for the logout request validation process like allow a clock drift when checking dates with :allowed_clock_drift
      #
      def initialize(request, options = {})
        @errors = []
        raise ArgumentError.new("Request cannot be nil") if request.nil?
        @options  = options
        @request = decode_raw_saml(request)
        @document = REXML::Document.new(@request)
      end

      # Validates the Logout Request with the default values (soft = true)
      # @return [Boolean] TRUE if the Logout Request is valid
      #
      def is_valid?
        validate
      end

      # Validates the Logout Request (soft = false)
      # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
      # @return [Boolean] TRUE if the Logout Request is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate!(soft=false)
        validate(soft)
      end

      # Gets the ID attribute from the Logout Request.
      # @return [String|nil] The ID value if exists.
      #
      def id
        super(self.document)
      end

      # Gets the NameID of the Logout Request.
      # @return [String] NameID Value
      #
      def name_id
        @name_id ||= begin
          node = REXML::XPath.first(self.document, "/p:LogoutRequest/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      # Gets the Destination attribute from the Logout Request.
      # @return [String|nil] The Destination value if exists.
      #
      def destination
        @destination ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes['Destination']
        end
      end

      # Gets the Issuer from the Logout Request.
      # @return [String] The Issuer
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(self.document, "/p:LogoutRequest/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      # Gets the NotOnOrAfter Attribute value if exists.
      # @return [Time|nil] The NotOnOrAfter value in Time format
      #
      def not_on_or_after
        @not_on_or_after ||= begin
          node = REXML::XPath.first(self.document, "/p:LogoutRequest", { "p" => PROTOCOL} )
          if node && node.attributes["NotOnOrAfter"]
            Time.parse(node.attributes["NotOnOrAfter"])
          else
            nil
          end
        end
      end

      # Gets the SessionIndex if exists (Supported multiple values). 
      # @return [Array] The Session Indexes. Empty Array if none found 
      #
      def session_indexes
        session_index = []
        nodes = REXML::XPath.match(self.document, "/p:LogoutRequest/p:SessionIndex", { "p" => PROTOCOL} )

        if nodes
          nodes.each { |node|
            session_index << node.text
          }
        end
        session_index
      end

      private

        # Gets the expected current_url
        # (Right now we read this url from the Sinle Logout Service of the Settings)
        # TODO: Calculate the real current_url and use it.
        # @return [String] The current url
        #
        def current_url
          @current_url ||= begin
            unless self.settings.nil? or self.settings.single_logout_service_url.nil?
              self.settings.single_logout_service_url
            end
          end
        end

        # Validates the Logout Request (calls several validation methods)
        # If fails, the attribute errors will contains the reason for the invalidation.
        # @param [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean|ValidationError] True if the Logout Request is valid, otherwise
        #                                   - False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        def validate(soft = true)
          @errors = []
          validate_request_state(soft) &&
          validate_id                  &&
          validate_version             &&
          validate_structure(soft)     &&
          validate_not_on_or_after     &&
          validate_destination(soft)   &&
          validate_issuer(soft)
        end

        # Validates that the Logout Request contains an ID 
        # If fails, the error is added to the errors array.
        # @return [Boolean] True if the Logout Request contains an ID, otherwise returns False
        #
        def validate_id()
          unless id
            @errors << "Missing ID attribute on Logout Request"
            return false
          end
          true
        end

        # Validates the SAML version (2.0)
        # If fails, the error is added to the errors array.
        # @return [Boolean] True if the Logout Request is 2.0, otherwise returns False
        #
        def validate_version()
          unless version(self.document) == "2.0"
            @errors << "Unsupported SAML version"
            return false
          end
          true
        end

        # Validates the time. (If the logout request was initialized with the :allowed_clock_drift option, the timing validations are relaxed by the allowed_clock_drift value)
        # If fails, the error is added to the errors array
        # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean|ValidationError] True if satisfies the conditions, otherwise:
        #                                   - False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_not_on_or_after(soft = true)
          now = Time.now.utc
          if not_on_or_after && now >= (not_on_or_after + (options[:allowed_clock_drift] || 0))
            @errors << "Current time is on or after NotOnOrAfter (#{now} >= #{not_on_or_after})"
            return soft ? false : validation_error("Current time is on or after NotOnOrAfter")
          end

          true
        end

        # Validates that the Logout Request provided in the initialization is not empty, 
        # If fails, the error is added to the errors array.
        # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean|ValidationError] True if the required info is found, otherwise
        #                                   - False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_request_state(soft = true)
          if request.nil? or request.empty?
            error_msg = "Blank Logout Request" 
            @errors << error_msg
            return soft ? false : validation_error(error_msg)
          end
          true
        end

        # Validates the Logout Request against the specified schema.
        # If fails, the error is added to the errors array
        # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean|ValidationError] True if the XML is valid, otherwise:
        #                                   - False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_structure(soft = true)
          xml = Nokogiri::XML(self.document.to_s)

          SamlMessage.schema.validate(xml).map do |error|
            if soft
              @errors << "Invalid Logout Request. Not match the saml-schema-protocol-2.0.xsd"
              break false
            else
              error_message = [error.message, xml.to_s].join("\n\n")

              @errors << error_message
              validation_error(error_message)
            end
          end
        end

        # Validates the Destination, (if the Logout Request is received where expected)
        # If fails, the error is added to the errors array
        # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean|ValidationError] True if the destination is valid, otherwise:
        #                                   - False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_destination(soft = true)
          return true if destination.nil? or destination.empty? or settings.single_logout_service_url.nil? or settings.single_logout_service_url.empty?

          unless destination == current_url
            error_msg = "The Logout Request was received at #{self.destination} instead of #{current_url}"
            @errors << error_msg
            return soft ? false : validation_error(error_msg)
          end

          true
        end

        # Validates the Issuer of the Logout Request
        # If fails, the error is added to the errors array
        # @param  [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean|ValidationError] True if the Issuer matchs the IdP entityId, otherwise:
        #                                   - False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_issuer(soft = true)
          return true if settings.idp_entity_id.nil? or issuer.nil?

          unless URI.parse(issuer) == URI.parse(self.settings.idp_entity_id)
            error_msg = "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>"
            @errors << error_msg
            return soft ? false : validation_error(error_msg)
          end

          true
        end

    end
  end
end

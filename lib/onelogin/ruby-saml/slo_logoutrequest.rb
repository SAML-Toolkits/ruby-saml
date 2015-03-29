require 'zlib'
require 'time'
require 'nokogiri'

require "onelogin/ruby-saml/saml_message"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Logout Request (SLO IdP initiated, Parser)
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
      # @param request [String] A UUEncoded Logout Request from the IdP.
      # @param options [Hash] Some options for the logout request validation process like allow a clock drift when checking dates with :allowed_clock_drift
      # @raise [ArgumentError]
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
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
      # @param get_params [Hash] In order to validate the In value we need to provide the GET parameters      
      # @return [Boolean] TRUE if the Logout Request is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate!(soft = false, get_params = nil)
        validate(soft, get_params)
      end

      # @return [String|nil] Gets the ID attribute from the Logout Request. if exists.
      #
      def id
        super(document)
      end

      # @return [String] Gets the NameID of the Logout Request.
      #
      def name_id
        @name_id ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      # @return [String|nil] Gets the Destination attribute from the Logout Request. if exists.
      #
      def destination
        @destination ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes['Destination']
        end
      end

      # @return [String] Gets the Issuer from the Logout Request.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      # @return [Time|nil] Gets the NotOnOrAfter Attribute value if exists.
      #
      def not_on_or_after
        @not_on_or_after ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest", { "p" => PROTOCOL} )
          if node && node.attributes["NotOnOrAfter"]
            Time.parse(node.attributes["NotOnOrAfter"])
          else
            nil
          end
        end
      end

      # @return [Array] Gets the SessionIndex if exists (Supported multiple values). Empty Array if none found 
      #
      def session_indexes
        session_index = []
        nodes = REXML::XPath.match(document, "/p:LogoutRequest/p:SessionIndex", { "p" => PROTOCOL} )

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
            if settings && settings.single_logout_service_url
              settings.single_logout_service_url
            end
          end
        end

        # Validates the Logout Request (calls several validation methods)
        # If fails, the attribute errors will contains the reason for the invalidation.
        # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @param get_params [Hash] In order to validate the In value we need to provide the GET parameters
        # @return [Boolean] True if the Logout Request is valid, otherwise False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate(soft = true, get_params = nil)
          @errors = []
          validate_request_state(soft) &&
          validate_id                  &&
          validate_version             &&
          validate_structure(soft)     &&
          validate_not_on_or_after     &&
          validate_destination(soft)   &&
          validate_issuer(soft)        &&
          validate_signature(soft, get_params)
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
          unless version(document) == "2.0"
            @errors << "Unsupported SAML version"
            return false
          end
          true
        end

        # Validates the time. (If the logout request was initialized with the :allowed_clock_drift option, the timing validations are relaxed by the allowed_clock_drift value)
        # If fails, the error is added to the errors array
        # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean] True if satisfies the conditions, otherwise False if soft=True
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
        # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean] True if the required info is found, otherwise False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_request_state(soft = true)
          if request.nil? || request.empty?
            error_msg = "Blank Logout Request" 
            @errors << error_msg
            return soft ? false : validation_error(error_msg)
          end
          true
        end

        # Validates the Logout Request against the specified schema.
        # If fails, the error is added to the errors array
        # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean] True if the XML is valid, otherwise False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_structure(soft = true)
          begin 
            valid = valid_saml?(document, soft)
            unless valid
              @errors << "Invalid Logout Request. Not match the saml-schema-protocol-2.0.xsd"
            end
            valid
          rescue OneLogin::RubySaml::ValidationError => e
            @errors << e.message
            raise e
          end
        end

        # Validates the Destination, (if the Logout Request is received where expected)
        # If fails, the error is added to the errors array
        # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean] True if the destination is valid, otherwise False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_destination(soft = true)
          return true if destination.nil? || destination.empty? || settings.single_logout_service_url.nil? || settings.single_logout_service_url.empty?

          unless destination == current_url
            error_msg = "The Logout Request was received at #{destination} instead of #{current_url}"
            @errors << error_msg
            return soft ? false : validation_error(error_msg)
          end

          true
        end

        # Validates the Issuer of the Logout Request
        # If fails, the error is added to the errors array
        # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout request is invalid or not)
        # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_issuer(soft = true)
          return true if settings.idp_entity_id.nil? || issuer.nil?

          unless URI.parse(issuer) == URI.parse(settings.idp_entity_id)
            error_msg = "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>"
            @errors << error_msg
            return soft ? false : validation_error(error_msg)
          end

          true
        end

      # Validates the Signature if exists and GET parameters are provided
      # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the logout response is invalid or not)
      # @param get_params [Hash] In order to validate the In value we need to provide the GET parameters
      # @return [Boolean] True if not contains a Signature or if the Signature is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #      
      def validate_signature(soft = true, get_params = nil)
        return true if get_params.nil? || get_params['Signature'].nil? || settings.nil? || settings.get_idp_cert.nil?
        
        query_string = OneLogin::RubySaml::Utils.build_query(
          :type        => 'SAMLRequest',
          :data        => get_params['SAMLRequest'],
          :relay_state => get_params['RelayState'],
          :sig_alg     => get_params['SigAlg']
        )

        valid = OneLogin::RubySaml::Utils.verify_signature(
          :cert         => settings.get_idp_cert,
          :sig_alg      => get_params['SigAlg'],
          :signature    => get_params['Signature'],
          :query_string => query_string
        )

        unless valid
          error_msg = "Invalid Signature on Logout Request"
          @errors << error_msg
          return soft ? false : validation_error(error_msg)
        end
        true
      end

    end
  end
end

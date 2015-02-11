require 'zlib'
require 'time'
require 'nokogiri'

# Only supports SAML 2.0
module OneLogin
  module RubySaml
    class SloLogoutrequest < SamlMessage
      attr_reader :options
      attr_reader :request
      attr_reader :document

      def initialize(request, options = {})
        @errors = []
        raise ArgumentError.new("Request cannot be nil") if request.nil?
        @options  = options
        @request = decode_raw_saml(request)
        @document = REXML::Document.new(@request)
      end

      def is_valid?
        validate
      end

      def validate!
        validate(false)
      end

      # The value of the user identifier as designated by the initialization request response
      def name_id
        @name_id ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      def id
        return @id if @id
        element = REXML::XPath.first(document, "/p:LogoutRequest", {
            "p" => PROTOCOL} )
        return nil if element.nil?
        return element.attributes["ID"]
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutRequest/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      private

      def validate(soft = true)
        @errors = []
        valid_saml?(document, soft)  &&
        validate_request_state(soft)
      end

      def validate_request_state(soft = true)
        if request.nil? or request.empty?
          return soft ? false : validation_error("Blank Logout Request")
        end
        true
      end

      def validate_conditions(soft = true)
        return true if conditions.nil?
        return true if options[:skip_conditions]

        now = Time.now.utc

        if not_before && (now + (options[:allowed_clock_drift] || 0)) < not_before
          @errors << "Current time is earlier than NotBefore condition #{(now + (options[:allowed_clock_drift] || 0))} < #{not_before})"
          return soft ? false : validation_error("Current time is earlier than NotBefore condition")
        end

        if not_on_or_after && now >= (not_on_or_after + (options[:allowed_clock_drift] || 0))
          @errors << "Current time is on or after NotOnOrAfter condition (#{now} >= #{not_on_or_after})"
          return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
        end

        true
      end

    end
  end
end

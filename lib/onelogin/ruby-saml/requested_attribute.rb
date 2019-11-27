module OneLogin
  module RubySaml

    # Class simplifying management of eidas:RequestedAttribute from eIDAS saml-extensions
    # It's implementation is intentionally vague to allow custom attributes of RequestedAttribute element and accept any kind of value
    class RequestedAttribute

      attr_accessor :attributes
      attr_accessor :value

      DEFAULTS = {
          :NameFormat => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'.freeze,
          :isRequired => false,
          :FriendlyName => false
      }.freeze

      # @param attrs [Hash] The +attrs+ must be Hash of known attributes, ie:
      #   RequestedAttribute.new({
      #     :Name => "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
      #     :FriendlyName => "DoB",
      #     :isRequired => false,
      #     :NameFormat => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      #   })
      # or if above mentioned defaults suit your needs, you can provide only RequestedAttribute Name
      #   RequestedAttribute.new({
      #     :Name = "http://www.stork.gov.eu/1.0/isAgeOver"
      #  }, 18)
      # @param [String|Object] val value of eidas:AttributeValue or nil if you don't want the element to be provided
      def initialize(attrs = {}, val = nil)
        @attributes = DEFAULTS.merge(attrs)
        @value = val
      end

      # @return [Hash]
      def stringify_attribute_keys
        Hash[attributes.collect { |k, v| [k.to_s, v] }]
      end

    end

  end
end
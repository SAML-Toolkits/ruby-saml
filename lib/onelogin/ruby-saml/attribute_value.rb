module OneLogin
  module RubySaml

    # Wrapper for AttributeValue with multiple values
    # It is subclass of String to be backwards compatible
    # Use AttributeValue#values to get all values as an array
    class AttributeValue < String
      attr_accessor :values
      def initialize(str="", values=[])
        @values = values
        super(str)
      end
    end
  end
end

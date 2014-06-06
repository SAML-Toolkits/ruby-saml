module OneLogin
  module RubySaml

    # Wrapper for AttributeValue with multiple values
    # It is subclass of String to be backwards compatible
    # Use AttributeValue#values to get all values as an array
    module AttributeValue
      def values
        @values ||= []
        @values
      end
      def values=(values)
        @values = values
      end
    end
  end
end

module OneLogin
  module RubySaml
    # Wraps all attributes and provides means to query them for single or multiple values.
    # 
    # For backwards compatibility Attributes#[] returns *first* value for the attribute.
    # Turn off compatibility to make it return all values as an array:
    #    Attributes.single_value_compatibility = false
    class Attributes
      include Enumerable

      # By default Attributes#[] is backwards compatible and
      # returns only the first value for the attribute
      # Setting this to `false` returns all values for an attribute
      @@single_value_compatibility = true

      # Get current status of backwards compatibility mode.
      def self.single_value_compatibility
        @@single_value_compatibility
      end

      # Sets the backwards compatibility mode on/off.
      def self.single_value_compatibility=(value)
        @@single_value_compatibility = value
      end

      # Initialize Attributes collection, optionally taking a Hash of attribute names and values.
      #
      # The +attrs+ must be a Hash with attribute names as keys and **arrays** as values:
      #    Attributes.new({
      #      'name' => ['value1', 'value2'],
      #      'mail' => ['value1'],
      #    })
      def initialize(attrs = {})
        @attributes = attrs
      end


      # Iterate over all attributes
      def each
        attributes.each{|name, values| yield name, values}
      end

      # Test attribute presence by name
      def include?(name)
        attributes.has_key?(canonize_name(name))
      end
      
      # Return first value for an attribute
      def single(name)
        attributes[canonize_name(name)].first if include?(name)
      end

      # Return all values for an attribute
      def multi(name)
        attributes[canonize_name(name)]
      end

      # By default returns first value for an attribute.
      #
      # Depending on the single value compatibility status this returns first value
      #    Attributes.single_value_compatibility = true # Default
      #    response.attributes['mail']  # => 'user@example.com'
      #
      # Or all values:
      #    Attributes.single_value_compatibility = false
      #    response.attributes['mail']  # => ['user@example.com','user@example.net']
      def [](name)
        self.class.single_value_compatibility ? single(canonize_name(name)) : multi(canonize_name(name))
      end

      # Return all attributes as an array
      def all
        attributes
      end

      # Set values for an attribute, overwriting all existing values
      def set(name, values)
        attributes[canonize_name(name)] = values
      end
      alias_method :[]=, :set

      # Add new attribute or new value(s) to an existing attribute
      def add(name, values = [])
        attributes[canonize_name(name)] ||= []
        attributes[canonize_name(name)] += Array(values)
      end

      # Make comparable to another Attributes collection based on attributes
      def ==(other)
        if other.is_a?(Attributes)
          all == other.all
        else
          super
        end
      end

      protected

      # stringifies all names so both 'email' and :email return the same result
      def canonize_name(name)
        name.to_s
      end

      def attributes
        @attributes
      end
    end
  end
end

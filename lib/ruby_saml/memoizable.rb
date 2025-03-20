# frozen_string_literal: true

module RubySaml
  # Mixin for memoizing methods
  module Memoizable
    # Creates a memoized method
    #
    # @param method_name [Symbol] the name of the method to memoize
    # @param original_method [Symbol, nil] the original method to memoize (defaults to method_name)
    def self.included(base)
      base.extend(ClassMethods)
    end

    private

    # Memoizes the result of a block using the given name as the cache key
    #
    # @param cache_key [Symbol, String] the name to use as the cache key
    # @yield the block whose result will be cached
    # @return [Object] the cached result or the result of the block
    def memoize(cache_key)
      cache_key = "@#{cache_key.to_s.delete_prefix('@')}"
      return instance_variable_get(cache_key) if instance_variable_defined?(cache_key)

      instance_variable_set(cache_key, yield)
    end

    # Class methods for memoization
    module ClassMethods
      # Defines multiple memoized methods
      #
      # @param method_names [Array<Symbol>] the names of the methods to memoize
      # @raise [ArgumentError] if any method has an arity greater than 0
      def memoize_method(*method_names)
        method_names.each do |method_name|
          method_obj = instance_method(method_name)

          # Check method arity
          if method_obj.arity > 0 # rubocop:disable Style/IfUnlessModifier
            raise ArgumentError.new("Cannot memoize method '#{method_name}' with arity > 0")
          end

          # Store the original method
          original_method_name = "#{method_name}_without_memoization"
          alias_method original_method_name, method_name
          private original_method_name

          # Define the memoized version
          define_method(method_name) do |&block|
            cache_key = "@memoized_#{method_name}"
            memoize(cache_key) do
              send(original_method_name, &block)
            end
          end

          # Preserve method visibility
          if private_method_defined?(original_method_name)
            private method_name
          elsif protected_method_defined?(original_method_name)
            protected method_name
          end
        end
      end
    end
  end
end

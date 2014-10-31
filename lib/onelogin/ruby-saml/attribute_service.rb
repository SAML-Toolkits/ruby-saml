module OneLogin
  module RubySaml
    class AttributeService
      attr_reader :attributes
      attr_reader :name
      attr_reader :index

      def initialize
        @index = "1"
        @attributes = []
      end

      def configure(&block)
        instance_eval &block
      end

      def configured?
        @attributes.length > 0 && !@name.nil?
      end

      def service_name(name)
        @name = name
      end

      def service_index(index)
        @index = index
      end
      
      def add_attribute(options={})
        attributes << options 
      end
    end
  end
end

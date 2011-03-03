require 'erb'

module Onelogin::Saml
  class EntityDescription
    def initialize()
      url = "entity_descriptor.xml.erb"
      @template = File.read(File.join(File.dirname(__FILE__), url))
    end

    def generate(values)
      entity_id = values[:entity_id]
      name_id_format = values[:name_id_format]
      assertion_consumer_service_location = values[:assertion_consumer_service_location]

      erb = ERB.new(@template)
      erb.result(binding)
    end
  end
end
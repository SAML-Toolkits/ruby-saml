# Simplistic log class when we're running in Rails
module OneLogin
  module RubySaml
    class Logging
      def self.logger=(logger)
        @logger = logger
      end
      def self.debug(message)
        return if !!ENV["ruby-saml/testing"]

        if defined? Rails
          Rails.logger.debug message
        else
          @logger.debug(message) unless @logger.nil?
        end
      end

      def self.info(message)
        return if !!ENV["ruby-saml/testing"]

        if defined? Rails
          Rails.logger.info message
        else
          @logger.info(message) unless @logger.nil?
        end
      end
    end
  end
end

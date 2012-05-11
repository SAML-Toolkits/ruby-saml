# Simplistic log class when we're running in Rails
module Onelogin
  module Saml
    class Logging
      def self.debug(message)
        return if !!ENV["ruby-saml/testing"]

        if defined? Rails
          Rails.logger.debug message
        else
          puts message
        end
      end

      def self.info(message)
        return if !!ENV["ruby-saml/testing"]

        if defined? Rails
          Rails.logger.info message
        else
          puts message
        end
      end
    end
  end
end

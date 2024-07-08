# frozen_string_literal: true

require 'logger'

# Simplistic log class when we're running in Rails
module RubySaml
  class Logging
    DEFAULT_LOGGER = ::Logger.new($stdout)

    def self.logger
      @logger ||= begin
        logger = Rails.logger if defined?(::Rails) && Rails.respond_to?(:logger)
        logger ||= DEFAULT_LOGGER
      end
    end

    class << self
      attr_writer :logger
    end

    def self.debug(message)
      return if ENV['ruby-saml/testing']

      logger.debug(message)
    end

    def self.info(message)
      return if ENV['ruby-saml/testing']

      logger.info(message)
    end
  end
end

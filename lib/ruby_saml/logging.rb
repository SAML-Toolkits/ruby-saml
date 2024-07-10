# frozen_string_literal: true

require 'logger'

module RubySaml
  module Logging
    extend self

    DEFAULT_LOGGER = ::Logger.new($stdout)

    attr_writer :logger

    def logger
      @logger ||= begin
        logger = Rails.logger if defined?(::Rails) && Rails.respond_to?(:logger)
        logger || DEFAULT_LOGGER
      end
    end

    %i[error warn debug info].each do |level|
      define_method(level) do |message|
        logger.send(level, message) if enabled?
      end
    end

    def deprecate(message)
      warn("[RubySaml] DEPRECATION: #{message}")
    end

    def enabled?
      !ENV['ruby-saml/testing']
    end
  end
end

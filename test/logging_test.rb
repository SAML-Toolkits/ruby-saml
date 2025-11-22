# frozen_string_literal: true

require_relative 'test_helper'

class LoggingTest < Minitest::Test

  describe "Logging" do
    before do
      RubySaml::Logging.logger = nil
    end

    after do
      RubySaml::Logging.logger = ::TEST_LOGGER
    end

    describe "given no specific logging setup" do
      it "prints to stdout" do
        RubySaml::Logging::DEFAULT_LOGGER.expects(:debug).with('hi mom')
        RubySaml::Logging.debug('hi mom')
      end
    end

    describe "given a Rails app" do
      let(:logger) { mock('Logger') }

      before do
        ::Rails = mock('Rails module')
        ::Rails.stubs(:logger).returns(logger)
      end

      after do
        Object.instance_eval { remove_const(:Rails) }
      end

      it "delegates to Rails" do
        logger.expects(:debug).with('hi mom')
        logger.expects(:info).with('sup?')

        RubySaml::Logging.debug('hi mom')
        RubySaml::Logging.info('sup?')
      end
    end

    describe "given a specific Logger" do
      let(:logger) { mock('Logger') }

      before { RubySaml::Logging.logger = logger }

      after do
        RubySaml::Logging.logger = ::TEST_LOGGER
      end

      it "delegates to the object" do
        logger.expects(:debug).with('hi mom')
        logger.expects(:info).with('sup?')

        RubySaml::Logging.debug('hi mom')
        RubySaml::Logging.info('sup?')
      end
    end

    describe "OneLogin::RubySaml::Logging compatibility" do
      it "defines OneLogin::RubySaml::Logging as an alias to RubySaml::Logging" do
        assert defined?(OneLogin::RubySaml::Logging),
               "Expected OneLogin::RubySaml::Logging to be defined"

        assert_equal RubySaml::Logging.object_id,
                     OneLogin::RubySaml::Logging.object_id,
                     "Expected OneLogin::RubySaml::Logging to alias RubySaml::Logging"
      end

      it "shares the same logger instance when set via RubySaml::Logging" do
        logger = mock('Logger')
        RubySaml::Logging.logger = logger

        assert_same logger, OneLogin::RubySaml::Logging.logger
      end

      it "shares the same logger instance when set via OneLogin::RubySaml::Logging" do
        logger = mock('Logger')
        OneLogin::RubySaml::Logging.logger = logger

        assert_same logger, RubySaml::Logging.logger
      end

      it "delegates to the configured logger when using the legacy constant" do
        logger = mock('Logger')
        OneLogin::RubySaml::Logging.logger = logger

        logger.expects(:debug).with('hi mom')
        logger.expects(:info).with('sup?')

        OneLogin::RubySaml::Logging.debug('hi mom')
        OneLogin::RubySaml::Logging.info('sup?')
      end

      it "respects ENV['ruby-saml/testing'] and does not log when set (legacy constant)" do
        logger = mock('Logger')
        OneLogin::RubySaml::Logging.logger = logger

        ENV["ruby-saml/testing"] = "1"

        # No expectations on logger; any call would cause Mocha to fail the test.
        OneLogin::RubySaml::Logging.debug('hi mom')
        OneLogin::RubySaml::Logging.info('sup?')
        OneLogin::RubySaml::Logging.warn('hey')
        OneLogin::RubySaml::Logging.error('oops')

        ENV.delete("ruby-saml/testing")
      end
    end
  end
end

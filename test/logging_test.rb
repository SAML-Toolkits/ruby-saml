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
  end
end

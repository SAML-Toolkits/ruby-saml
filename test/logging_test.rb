require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/logging'

class LoggingTest < Minitest::Test

  describe "Logging" do
    before do
      ENV.delete('ruby-saml/testing')
    end

    after do
      ENV['ruby-saml/testing'] = '1'
    end

    describe "given no specific logging setup" do
      it "prints to stdout" do
        OneLogin::RubySaml::Logging.expects(:puts).with('hi mom')
        OneLogin::RubySaml::Logging.debug('hi mom')
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

        OneLogin::RubySaml::Logging.debug('hi mom')
        OneLogin::RubySaml::Logging.info('sup?')
      end
    end
  end
end

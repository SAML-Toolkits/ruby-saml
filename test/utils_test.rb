require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class UtilsTest < Minitest::Test

  describe "Utils" do

    describe ".uuid" do
      it "returns a uuid starting with an underscore" do
        assert_match /^_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, OneLogin::RubySaml::Utils.uuid
      end

      it "doesn't return the same value twice" do
        refute_equal OneLogin::RubySaml::Utils.uuid, OneLogin::RubySaml::Utils.uuid
      end
    end
  end
end

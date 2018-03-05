require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class UtilsTest < Test::Unit::TestCase
  context "Utils" do
    context 'element_text' do
      should 'returns the element text' do
        element = REXML::Document.new('<element>element text</element>').elements.first
        assert_equal 'element text', OneLogin::RubySaml::Utils.element_text(element)
      end

      should 'returns all segments of the element text' do
        element = REXML::Document.new('<element>element <!-- comment -->text</element>').elements.first
        assert_equal 'element text', OneLogin::RubySaml::Utils.element_text(element)
      end

      should 'returns normalized element text' do
        element = REXML::Document.new('<element>element &amp; text</element>').elements.first
        assert_equal 'element & text', OneLogin::RubySaml::Utils.element_text(element)
      end

      should 'returns the CDATA element text' do
        element = REXML::Document.new('<element><![CDATA[element & text]]></element>').elements.first
        assert_equal 'element & text', OneLogin::RubySaml::Utils.element_text(element)
      end

      should 'returns the element text with newlines and additional whitespace' do
        element = REXML::Document.new("<element>  element \n text  </element>").elements.first
        assert_equal "  element \n text  ", OneLogin::RubySaml::Utils.element_text(element)
      end

      should 'returns nil when element is nil' do
        assert_nil OneLogin::RubySaml::Utils.element_text(nil)
      end

      should 'returns empty string when element has no text' do
        element = REXML::Document.new('<element></element>').elements.first
        assert_equal '', OneLogin::RubySaml::Utils.element_text(element)
      end
    end
  end
end
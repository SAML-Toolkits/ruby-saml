require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class UtilsTest < Minitest::Test
  describe "Utils" do
    describe 'element_text' do
      it 'returns the element text' do
        element = REXML::Document.new('<element>element text</element>').elements.first
        assert_equal 'element text', OneLogin::RubySaml::Utils.element_text(element)
      end

      it 'returns all segments of the element text' do
        element = REXML::Document.new('<element>element <!-- comment -->text</element>').elements.first
        assert_equal 'element text', OneLogin::RubySaml::Utils.element_text(element)
      end

      it 'returns normalized element text' do
        element = REXML::Document.new('<element>element &amp; text</element>').elements.first
        assert_equal 'element & text', OneLogin::RubySaml::Utils.element_text(element)
      end

      it 'returns the CDATA element text' do
        element = REXML::Document.new('<element><![CDATA[element & text]]></element>').elements.first
        assert_equal 'element & text', OneLogin::RubySaml::Utils.element_text(element)
      end

      it 'returns the element text with newlines and additional whitespace' do
        element = REXML::Document.new("<element>  element \n text  </element>").elements.first
        assert_equal "  element \n text  ", OneLogin::RubySaml::Utils.element_text(element)
      end

      it 'returns nil when element is nil' do
        assert_nil OneLogin::RubySaml::Utils.element_text(nil)
      end

      it 'returns empty string when element has no text' do
        element = REXML::Document.new('<element></element>').elements.first
        assert_equal '', OneLogin::RubySaml::Utils.element_text(element)
      end
    end
  end
end
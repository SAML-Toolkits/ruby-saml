# frozen_string_literal: true

require_relative 'test_helper'

class AttributesTest < Minitest::Test
  describe 'Attributes' do
    let(:attributes) do
      RubySaml::Attributes.new({
        'email' => ['tom@hanks.com'],
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname' => ['Tom'],
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname' => ['Hanks']
      })
    end

    it 'fetches string attribute' do
      assert_equal('tom@hanks.com', attributes.fetch('email'))
    end

    it 'fetches symbol attribute' do
      assert_equal('tom@hanks.com', attributes.fetch(:email))
    end

    it 'fetches regexp attribute' do
      assert_equal('Tom', attributes.fetch(/givenname/))
      assert_equal('Tom', attributes.fetch(/gi(.*)/))
      assert_nil(attributes.fetch(/^z.*/))
      assert_equal('Hanks', attributes.fetch(/surname/))
    end
  end
end

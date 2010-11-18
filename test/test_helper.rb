require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'mocha'

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'ruby-saml'

class Test::Unit::TestCase
  def response_document
    @response_document ||= File.read(File.join(File.dirname(__FILE__), 'response.txt'))
  end
end

require 'onelogin/ruby-saml/logging'
require 'onelogin/ruby-saml/authrequest'
require 'onelogin/ruby-saml/logoutrequest'
require 'onelogin/ruby-saml/logoutresponse'
require 'onelogin/ruby-saml/response'
require 'onelogin/ruby-saml/settings'
require 'onelogin/ruby-saml/validation_error'
require 'onelogin/ruby-saml/metadata'
require 'onelogin/ruby-saml/version'

module Onelogin
  module Saml
    def self.jars_root
      File.join("#{File.dirname(__FILE__)}", "jars")
    end

    def self.load_jars!
      require 'java'
      Dir["#{jars_root}/*.jar"].each { |jar| require jar }
    end

  end
end

Onelogin::Saml.load_jars! if RUBY_ENGINE == "jruby"
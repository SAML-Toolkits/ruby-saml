lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require "onelogin/ruby-saml/version"

Gem::Specification.new do |spec|
  spec.name        = "ruby-saml"
  spec.version     = OneLogin::RubySaml::VERSION
  spec.authors     = ["OneLogin LLC"]
  spec.email       = ["support@onelogin.com"]
  spec.summary     = "SAML Ruby Tookit"
  spec.description = "SAML toolkit for Ruby on Rails"
  spec.license     = "MIT"
  spec.homepage    = "http://github.com/onelogin/ruby-saml"

  spec.files       = `git ls-files -z`.split("\x0")
  spec.executables = spec.files.grep(/^bin/) { |f| File.basename(f) }
  spec.test_files  = spec.files.grep(/^test/)
  spec.require_paths = ["lib"]

  spec.add_dependency "nokogiri", "~> 1.6.6"
  spec.add_dependency "uuid", "~> 2.3.8"

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "minitest", "~> 5.5"
  spec.add_development_dependency "mocha", "~> 1.1.0"
  if defined?(JRUBY_VERSION)
    spec.add_development_dependency "pry", "~> 0.10.1"
  else
    spec.add_development_dependency "pry-byebug", "~> 3.2.0"
  end
  spec.add_development_dependency "rake", "~> 10.4"
  spec.add_development_dependency "shoulda", "~> 3.5.0"
  spec.add_development_dependency "timecop", "~> 0.8.0"
  spec.add_development_dependency "simplecov", "~> 0.10.0"
end

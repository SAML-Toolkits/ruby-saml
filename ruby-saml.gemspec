$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'onelogin/ruby-saml/version'

Gem::Specification.new do |s|
  s.name = 'ruby-saml'
  s.version = OneLogin::RubySaml::VERSION

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["SAML Toolkit", "Sixto Martin"]
  s.email = ['contact@iamdigitalservices.com', 'sixto.martin.garcia@gmail.com']
  s.date = Time.now.strftime("%Y-%m-%d")
  s.description = %q{SAML Ruby toolkit. Add SAML support to your Ruby software using this library}
  s.license = 'MIT'
  s.extra_rdoc_files = [
    "LICENSE",
    "README.md"
  ]
  s.files = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  s.homepage = %q{https://github.com/saml-toolkits/ruby-saml}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.required_ruby_version = '>= 1.8.7'
  s.summary = %q{SAML Ruby Tookit}

  s.add_runtime_dependency('nokogiri', '>= 1.13.10')
  s.add_runtime_dependency('rexml')

  s.add_development_dependency('simplecov', '<0.22.0')
  s.add_development_dependency('simplecov-lcov', '>0.7.0')
  s.add_development_dependency('minitest', '~> 5.5', '<5.19.0')
  s.add_development_dependency('mocha',    '~> 0.14')
  s.add_development_dependency('rake',     '>= 12.3.3')
  s.add_development_dependency('shoulda',  '~> 2.11')
  s.add_development_dependency('systemu',  '~> 2')
  s.add_development_dependency('timecop',  '~> 0.9')
end

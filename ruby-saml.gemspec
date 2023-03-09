$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'ruby_saml/version'

Gem::Specification.new do |s|
  s.name = 'ruby-saml'
  s.version = RubySaml::VERSION

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
  s.required_ruby_version = '>= 2.6.0'
  s.summary = %q{SAML Ruby Tookit}

  s.add_dependency('nokogiri', '>= 1.13.10')
  s.add_dependency('rexml')
end

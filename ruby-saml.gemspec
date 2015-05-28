$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'onelogin/ruby-saml/version'

Gem::Specification.new do |s|
  s.name = 'ruby-saml'
  s.version = OneLogin::RubySaml::VERSION

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["OneLogin LLC"]
  s.date = Time.now.strftime("%Y-%m-%d")
  s.description = %q{SAML toolkit for Ruby on Rails}
  s.email = %q{support@onelogin.com}
  s.license = 'MIT'
  s.extra_rdoc_files = [
    "LICENSE",
     "README.md"
  ]
  s.files = `git ls-files`.split("\n")
  s.homepage = %q{http://github.com/onelogin/ruby-saml}
  s.rubyforge_project = %q{http://www.rubygems.org/gems/ruby-saml}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.required_ruby_version = '>= 1.8.7'
  s.summary = %q{SAML Ruby Tookit}
  s.test_files = `git ls-files test/*`.split("\n")

  s.add_runtime_dependency('uuid', '~> 2.3')

  # Because runtime dependencies are determined at build time, we cannot make
  # Nokogiri's version dependent on the Ruby version, even though we would
  # have liked to constrain Ruby 1.8.7 to install only the 1.5.x versions.
  s.add_runtime_dependency('nokogiri', '>= 1.5.10')

  s.add_development_dependency('minitest', '~> 5.5')
  s.add_development_dependency('mocha',    '~> 0.14')
  s.add_development_dependency('rake',     '~> 10')
  s.add_development_dependency('shoulda',  '~> 2.11')
  s.add_development_dependency('simplecov','~> 0.9.0')
  s.add_development_dependency('systemu',  '~> 2')
  s.add_development_dependency('timecop',  '<= 0.6.0')

  if RUBY_VERSION < '1.9'
    # 1.8.7
    s.add_development_dependency('ruby-debug', '~> 0.10.4')
  elsif RUBY_VERSION < '2.0'
    # 1.9.x
    s.add_development_dependency('debugger-linecache', '~> 1.2.0')
    s.add_development_dependency('debugger', '~> 1.6.4')
  elsif RUBY_VERSION < '2.1'
    # 2.0.x
    s.add_development_dependency('byebug', '~> 2.1.1')
  else
    # 2.1.x, 2.2.x
    s.add_development_dependency('pry-byebug')
  end
end

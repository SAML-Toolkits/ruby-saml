$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'onelogin/ruby-saml/version'

Gem::Specification.new do |s|
  s.name = 'ruby-saml'
  s.version = Onelogin::Saml::VERSION

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["OneLogin LLC"]
  s.date = Time.now.strftime("%Y-%m-%d")
  s.description = %q{SAML toolkit for Ruby on Rails}
  s.email = %q{support@onelogin.com}
  s.extra_rdoc_files = [
    "LICENSE",
     "README.rdoc"
  ]
  s.files = `git ls-files`.split("\n")
  s.homepage = %q{http://github.com/onelogin/ruby-saml}
  s.rubyforge_project = %q{http://www.rubygems.org/gems/ruby-saml}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.summary = %q{SAML Ruby Tookit}
  s.test_files = `git ls-files test/*`.split("\n")

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<canonix>, ["~> 0.1"])
      s.add_runtime_dependency(%q<uuid>, ["~> 2.3"])
      s.add_development_dependency(%q<shoulda>, [">= 0"])
      s.add_development_dependency(%q<ruby-debug>, [">= 0"])
      s.add_development_dependency(%q<mocha>, [">= 0"])
    else
      s.add_dependency(%q<canonix>, ["~> 0.1"])
      s.add_dependency(%q<uuid>, ["~> 2.3"])
      s.add_dependency(%q<shoulda>, [">= 0"])
      s.add_dependency(%q<ruby-debug>, [">= 0"])
      s.add_dependency(%q<mocha>, [">= 0"])
    end
  else
    s.add_dependency(%q<canonix>, ["~> 0.1"])
    s.add_dependency(%q<uuid>, ["~> 2.3"])
    s.add_dependency(%q<shoulda>, [">= 0"])
    s.add_dependency(%q<ruby-debug>, [">= 0"])
    s.add_dependency(%q<mocha>, [">= 0"])
  end
end


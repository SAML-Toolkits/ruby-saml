require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "ruby-saml"
    gem.summary = %Q{SAML Ruby Tookit}
    gem.description = %Q{SAML toolkit for Ruby on Rails}
    gem.email = "support@onelogin.com"
    gem.homepage = "http://github.com/onelogin/ruby-saml"
    gem.authors = ["OneLogin LLC"]
    gem.add_dependency("xmlcanonicalizer","= 0.1.0")
    gem.add_dependency("uuid","= 2.3.1")
    gem.add_development_dependency "shoulda"
    gem.add_development_dependency "mocha"
    #gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end

#not being used yet.
require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new do |test|
    test.libs << 'test'
    test.pattern = 'test/**/*_test.rb'
    test.verbose = true
  end
rescue LoadError
  task :rcov do
    abort "RCov is not available. In order to run rcov, you must: sudo gem install spicycode-rcov"
  end
end

task :test => :check_dependencies

task :default => :test

# require 'rake/rdoctask'
# Rake::RDocTask.new do |rdoc|
#   if File.exist?('VERSION')
#     version = File.read('VERSION')
#   else
#     version = ""
#   end

#   rdoc.rdoc_dir = 'rdoc'
#   rdoc.title = "ruby-saml #{version}"
#   rdoc.rdoc_files.include('README*')
#   rdoc.rdoc_files.include('lib/**/*.rb')
#end

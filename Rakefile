require "bundler/gem_tasks"

task default: :test

# minitest
require "rake/testtask"
Rake::TestTask.new(:test) do |test|
  test.libs << "lib" << "test"
  test.pattern = "test/**/*_test.rb"
  test.verbose = true
end

# license finder
desc "Run `license_finder` to verify dependencies"
task :license_finder do
  sh "bundle exec license_finder --quiet"
end

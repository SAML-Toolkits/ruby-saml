#
# Please keep this file alphabetized and organized
#
source 'http://rubygems.org'

gemspec

group :test do
  if RUBY_VERSION < '1.9'
    gem 'nokogiri',   '~> 1.5.0'
    gem 'ruby-debug', '~> 0.10.4'
  elsif RUBY_VERSION < '2.0'
    gem 'debugger-linecache', '~> 1.2.0'
    gem 'debugger', '~> 1.6.4'
  elsif RUBY_VERSION < '2.1'
    gem 'byebug',   '~> 2.1.1'
  else
    gem 'pry-byebug'
  end

  gem 'mocha',     '~> 0.14',  :require => false
  gem 'rake',      '~> 10'
  gem 'shoulda',   '~> 2.11'
  gem 'systemu',   '~> 2'
  gem 'test-unit', '~> 3'
  gem 'timecop',   '<= 0.6.0'
end

source 'http://rubygems.org'

gemspec

group :test do
  platform :ruby_18 do
    gem "ruby-debug", "~> 0.10.4", :require => nil
  end
  platform :ruby_19 do
    gem "debugger",   "~> 1.1.1",  :require => nil
  end
  platform :jruby do
    gem "ruby-debug-base",   :require => nil
    gem "ruby-debug", "~> 0.10.4", :require => nil
  end

  gem "shoulda"
  gem "rake"
  gem "mocha"
  gem "nokogiri", ">= 1.5.0"
  gem "timecop"
end

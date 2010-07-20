class ApplicationController < ActionController::Base
  protect_from_forgery 

  before_filter :force_plugin_reload

  def force_plugin_reload
    ActiveSupport::Dependencies.load_file "xml_sec.rb" if "development" == RAILS_ENV
    ActiveSupport::Dependencies.load_file "xmlcanonicalizer.rb" if "development" == RAILS_ENV
  end
end

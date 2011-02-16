# Filters added to this controller apply to all controllers in the application.
# Likewise, all the methods added will be available for all controllers.

class ApplicationController < ActionController::Base
  helper :all # include all helpers, all the time
  protect_from_forgery # See ActionController::RequestForgeryProtection for details
  
  
  # products_controller.rb
  before_filter :authenticate
  filter_parameter_logging :passwd

  protected

  def authenticate
    authenticate_or_request_with_http_basic do |username, password|
      Authorization.current_user = User.find(:first,:conditions => ["name = ? AND passwd = ?",username,password])
    end
  end


  # Scrub sensitive parameters from your log
end

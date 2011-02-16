class User < ActiveRecord::Base
  def role_symbols
    [:user]
  end
end

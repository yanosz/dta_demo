class Project < ActiveRecord::Base
  using_access_control :include_attributes => [ :protect_ar => [:proxies,:attributes],
                                                :whitelist => [:user_id]
                                              ]
  belongs_to :owner, :class_name => "User"
end

authorization do
  role :user do
    has_permission_on :projects, :to => [:read_owner,:read_name]
    
    has_permission_on :projects, :to => [:read,:write] do
      if_attribute :user_id => is { user.id }
      if_attribute :user_id => is { nil }
      
    end
  end
end
# Be sure to restart your server when you modify this file.

# Your secret key for verifying cookie session data integrity.
# If you change this key, all old sessions will become invalid!
# Make sure the secret is at least 30 characters and all random, 
# no regular words or you'll be exposed to dictionary attacks.
ActionController::Base.session = {
  :key         => '_dta_demo_session',
  :secret      => '4ee6d558a69cabdbf9ef384a4e7e70a9ae6f8cced2646ab9c7ef4cde05d5211deaf098f15ab2209aed8707b23a34e1de50f79884f6ded8e0f2ebc90e6d387ff7'
}

# Use the database for sessions instead of the cookie-based default,
# which shouldn't be used to store highly confidential information
# (create the session table with "rake db:sessions:create")
# ActionController::Base.session_store = :active_record_store

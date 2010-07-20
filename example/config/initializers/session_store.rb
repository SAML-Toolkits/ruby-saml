# Be sure to restart your server when you modify this file.

# Your secret key for verifying cookie session data integrity.
# If you change this key, all old sessions will become invalid!
# Make sure the secret is at least 30 characters and all random, 
# no regular words or you'll be exposed to dictionary attacks.
ActionController::Base.session = {
  :key         => '_samlrp_session',
  :secret      => '1962dafb6507bf4a2ecf7cbc0dbfab4b440cff7ab67a7e2133005709d3dc87c368db91f4ab92539eee356cef488eeaf224cc5fcbce934af85d91e1e04cfccd89'
}

# Use the database for sessions instead of the cookie-based default,
# which shouldn't be used to store highly confidential information
# (create the session table with "rake db:sessions:create")
# ActionController::Base.session_store = :active_record_store

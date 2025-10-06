# change to true if want to send real aws ses emails 
export SEND_VERIFICATION_EMAILS=false
bundle exec ruby app.rb

## by default Sinatra listens on localhost:4567
## test endpoints on http://localhost:4567

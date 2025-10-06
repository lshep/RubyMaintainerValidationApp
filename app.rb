require 'sinatra'
require_relative './core'

post '/send-verification' do
  begin
    payload = request.body.read
    base_url = request.base_url
    status_code, response_body = Core.process_verification_payload(payload, base_url)
    status status_code
    content_type :json
    response_body
  rescue => e
    puts "Error: #{e.message}"
    status 500
    { error: e.message }.to_json
  end
end

post '/add-entries' do
  status_code, response_body = Core.process_new_entries_payload(request.body.read)
  status status_code
  content_type :json
  response_body
end

post '/sns/notifications' do
  request.body.rewind
  payload = request.body.read
  status, message = Core.process_sns_notification(payload)
  status status
  message
end

get '/' do
  send_file File.join(settings.public_folder, 'description.html')
end

get '/acceptpolicies/:email/:action/:password' do
  return Core.accept_policies(params[:email], params[:action], params[:password])
end

get '/info/package/:pkg' do
  content_type :json
  return Core.get_package_info(params[:pkg])
end

get %r{/info/name/(.+)} do |name|
  content_type :json
  return Core.get_name_info(name)
end

get '/info/email/:email' do
  content_type :json
  return Core.get_email_info(params[:email])
end

get '/info/valid/:email' do
  content_type :json
  return Core.is_email_valid(params[:email])
end

get '/list/invalid/' do
  content_type :json
  return Core.list_invalid()
end

get '/list/needs-consent/' do
  content_type :json
  return Core.list_needs_consent()
end

get '/list/bademails/' do
  content_type :json
  return Core.list_bad_emails()
end

get '/download-maintainer-db' do
  content_type 'application/json'
  data = Core.get_filtered_db_dump
  data.to_json
end

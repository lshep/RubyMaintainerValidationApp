require 'json'
require 'sqlite3'
require 'bcrypt'
require 'securerandom'
require 'aws-sdk-ses'
require 'aws-sdk-sesv2'
require 'date'
require 'logger'

class String
  # Strip leading whitespace from each line that is the same as the
  # amount of whitespace on the first line of the string.
  # Leaves _additional_ indentation on later lines intact.
  def unindent()
    gsub(/^#{self[/\A[ \t]*/]}/,'')
  end
end

class CoreConfig
  @@request_uri  = nil
  @@db = nil
  def self.set_request_uri(request_uri)
    @@request_uri = request_uri
  end
  def self.request_uri
    @@request_uri
  end
  def self.set_db(db)
    @@db = db
  end
  def self.db
    @@db
  end
end

module Core

dbfile = File.join(File.dirname(__FILE__), "db.sqlite3")

  need_schema = !File.exist?(dbfile) || File.size(dbfile) == 0
  db = SQLite3::Database.new(dbfile)
  CoreConfig.set_db(db)

  if need_schema
    db.execute <<-SQL.unindent
      CREATE TABLE maintainers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        consent_date DATE,
        pw_hash VARCHAR(255),
        email_status VARCHAR(50),
        is_email_valid BOOLEAN,
        last_verification_sent DATE,
        bounce_type VARCHAR(50),
        bounce_subtype VARCHAR(50),
        smtp_status VARCHAR(10),
        diagnostic_code TEXT,
        UNIQUE(package, email)
      );
    SQL
  end

  
  def Core.logger
    @logger ||= begin
                  log_path = if Dir.exist?("/opt/RubyMaintainerValidationApp/shared")
                               "/opt/RubyMaintainerValidationApp/shared/ses_debug.log"
                             else
                               "./ses_debug.log"  # fallback to current directory
                             end
                  
                  # Monthly rotation, keep 4 old logs
                  log = Logger.new(log_path, "monthly", 4)
                  log.level = Logger::INFO
                  log.formatter = proc do |severity, datetime, _progname, msg|
                    "[#{datetime}] #{severity}: #{msg}\n"
                  end
                  log
                end
  end

    
  def Core.process_verification_payload(payload, base_url)
    if CoreConfig.request_uri.nil?
      CoreConfig.set_request_uri(base_url)
    end
    begin
      payload = JSON.parse(payload)
    rescue JSON::ParserError
      return [400, "Invalid JSON"]
    end

    unless payload.is_a?(Array)
      return [400, "Expected an array of maintainers"]
    end

    results = []

    payload.uniq { |entry| entry['email'] }.each do |entry|
      email = entry['email']
      name = entry['name'] || "Maintainer"

      begin
        result = Core.handle_verify_email({'email' => email, 'name' => name})
        results << { email: email, status: "success", message: result }
      rescue => e
        results << { email: email, status: "error", message: e.message }
      end
    end

    [200, { results: results }.to_json]
  end


  def Core.handle_verify_email(obj)
    email = obj['email']
    name = obj['name'] || "Maintainer"
    
    Core.logger.info "Processing verification for #{email}"

    row = CoreConfig.db.get_first_row(
      "SELECT pw_hash, last_verification_sent FROM maintainers WHERE email = ?",
      [email]
    )
    existing_hash = row && row[0]
    last_sent_date = row && row[1]

    resend_threshold_days = 14
    
    if last_sent_date
      last_date = Date.parse(last_sent_date) rescue nil
      if last_date && (Date.today - last_date) < resend_threshold_days
        Core.logger.info "Verification email already sent recently (on #{last_date}) for #{email}. Skipping re-send."
        return "Verification email already sent recently (on #{last_date}). Skipping re-send."
      end
    end
    
    password = SecureRandom.hex(20)
    hash = BCrypt::Password.create(password)

    CoreConfig.db.execute("UPDATE maintainers SET pw_hash = ?, last_verification_sent = ? WHERE email = ?",
                          [hash, Date.today.to_s, email])
    
    ## puts "Would send email to #{email} (#{name}) with password: #{password}"
    return Core.email_validation_request(name, email, password)
    
  end

  
  def Core.email_validation_request(name, email, password)
    recipient_email = email
    recipient_name = name
    from_email = "bioc-validation-noreply@bioconductor.org"
    from_name = "Bioconductor Core Team"
    msg = <<-END.unindent
      Hi #{name},
      
      This email is associated with at least one Bioconductor package.
      Bioconductor periodically will confirm valid maintainer emails and
      remind maintainers of Bioconductor policies and expectations. Failure to
      accept bioconductor policies by clicking the link below may result in
      package deprecation and removal. 

      Please review the Bioconductor:

        1. Code of Conduct: https://bioconductor.org/about/code-of-conduct/
        2. Maintainer Expectations: https://contributions.bioconductor.org/bioconductor-package-submissions.html#author
        3. Deprecation Practices: https://contributions.bioconductor.org/package-end-of-life-policy.html
            

      To accept the above Bioconductor policies, please click on the following
      link, which will register your approval: #{CoreConfig.request_uri}/acceptpolicies/#{email}/accept/#{password}
 
      Please don't reply to this email. For questions or concerns please reach
      out on the bioc-devel@r-project.org mailing list.

      Thank you,

      The Bioconductor Core Team.
    END
    Core.send_email("#{from_name} <#{from_email}>",
      "#{recipient_name} <#{recipient_email}>",
      "Action required: Please Verify Bioconductor Policies",
      msg)
  end

  
  def Core.get_ses_client
    region = ENV['AWS_REGION'] || 'us-east-1'

    if ENV['AWS_ACCESS_KEY_ID'] && ENV['AWS_SECRET_ACCESS_KEY']
      creds = Aws::Credentials.new(
        ENV['AWS_ACCESS_KEY_ID'],
        ENV['AWS_SECRET_ACCESS_KEY']
      )

      Aws::SES::Client.new(
        region: region,
        credentials: creds
      )
    else
      Aws::SES::Client.new(region: region)
    end
  end

  
  def Core.get_ses_client_v2
    region = ENV['AWS_REGION'] || 'us-east-1'

    if ENV['AWS_ACCESS_KEY_ID'] && ENV['AWS_SECRET_ACCESS_KEY']
      creds = Aws::Credentials.new(
        ENV['AWS_ACCESS_KEY_ID'],
        ENV['AWS_SECRET_ACCESS_KEY']
      )

      Aws::SESV2::Client.new(
        region: region,
        credentials: creds
      )
    else
      Aws::SESV2::Client.new(region: region)
    end
  end


  def Core.send_email(from, to, subject, message)

    if ENV['SEND_VERIFICATION_EMAILS'] == 'true'

      ses = Core.get_ses_client

      begin
        ses.send_email({
                         source: from, 
                         destination: { to_addresses: [to] },
                         message: {
                           subject: {
                             data: subject,
                             charset: "UTF-8",
                           },
                           body: { 
                             text: {
                               data: message,
                               charset: "UTF-8",
                             }
                           },
                         },
                         configuration_set_name: "BioconductorMaintainerValidationConfig",
                         tags: [
                           { name: "App", value: "BioconductorMaintainerValidation" }
                         ]
                       })
        Core.logger.info "Email successfully sent to #{to}"
      rescue Aws::SES::Errors::ServiceError => e
        Core.logger.error "Failed to send email to #{to}: #{e.message}"
      end
        
    else

      Core.logger.info "=== Mock send_email called === "
      Core.logger.info "From: #{from}"
      Core.logger.info "To: #{to}"
      Core.logger.info "Subject: #{subject}"
      Core.logger.info "Message: \n #{message}"
      Core.logger.info "==============================="
    end
  end

  
  def Core.get_entries_by_email(email)
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      rows = CoreConfig.db.execute(
        "SELECT * FROM maintainers WHERE email = ?",
        email
      )
      return rows
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end


  def Core.accept_policies(email, action, password)
    entries = Core.get_entries_by_email(email)

    return "No entries found for this email." if entries.empty?

    matched = false
    consent_date = Date.today.to_s
  
    entries.each do |entry|
      pw_hash = entry['pw_hash']

      next if pw_hash.nil? || pw_hash.strip.empty?

      begin
        if BCrypt::Password.new(pw_hash) == password
          CoreConfig.db.execute(
            "UPDATE maintainers SET consent_date = ?, email_status = 'valid', is_email_valid = 1 WHERE id = ?",
            [consent_date, entry['id']]
          )
          matched = true
        end
      rescue BCrypt::Errors::InvalidHash => e
        next
      end
    end

    if matched
      return "Thank you! Your policy acceptance has been recorded."
    else
      return "Confirmation"
    end
  end

 
  def Core.process_new_entries_payload(request_body)
    begin
      payload = JSON.parse(request_body)
    rescue JSON::ParserError
      return [400, "Invalid JSON"]
    end
    
    unless payload.is_a?(Array)
      return [400, "Expected an array of entries"]
    end
    
    results = []

    payload.each do |entry|
      begin
        message = Core.handle_new_entries(entry)
        results << { email: entry['email'], package: entry['package'], status: "success", message: message }
      rescue => e
        results << { email: entry['email'], package: entry['package'], status: "error", message: e.message }
      end
    end
    
    [200, { results: results }.to_json]
  end


  def Core.handle_new_entries(entry)

    package = entry['package']
    name = entry['name'] || "Maintainer"
    email = entry['email']
       
    Core.add_entry_to_db(package, name, email)
    return "new entry added for package #{package} and email #{email}"
  end

  
  def Core.add_entry_to_db(package, name, email)
    consent_date = Date.today.to_s
    CoreConfig.db.execute "insert into maintainers (package, name, email, consent_date, email_status, is_email_valid) values (?,?,?,?,?,?)",
                          [package, name, email, consent_date, "new", 1]
  end

    
  def Core.get_package_info(package)
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      info = CoreConfig.db.execute("SELECT DISTINCT package, name, email, consent_date, email_status, is_email_valid FROM maintainers WHERE package = ?", package)
      return info.to_json
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end

  
  def Core.get_name_info(name)
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      info = CoreConfig.db.execute("SELECT DISTINCT name, package, email, consent_date, email_status, is_email_valid FROM maintainers WHERE name = ?", name)
      return info.to_json
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end


  def Core.get_email_info(email)
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      info = CoreConfig.db.execute("SELECT DISTINCT email, name, package, consent_date, email_status, is_email_valid FROM maintainers WHERE email = ?", email)
      return info.to_json
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end

  
  def Core.is_email_valid(email)
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      info = CoreConfig.db.execute("SELECT DISTINCT email, name, package,
  consent_date, email_status, is_email_valid, bounce_type, bounce_subtype,
  smtp_status, diagnostic_code FROM maintainers WHERE email = ?", email)

    return { valid: false }.to_json if info.empty?

    if info.all? { |row| row["is_email_valid"] == 1 }
      return { valid: true }.to_json
    end

    { valid: false, data: info }.to_json
     
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end

  
  ## def Core.list_invalid()
  ##  emails = CoreConfig.db.execute("SELECT DISTINCT email FROM maintainers WHERE is_email_valid IS NULL OR is_email_valid = 0")
  ##  return emails.to_json
  ## end

  
  def Core.list_invalid()
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      rows = CoreConfig.db.execute("
        SELECT DISTINCT email, name, package, email_status,
                        bounce_type, bounce_subtype, smtp_status, diagnostic_code
        FROM maintainers
        WHERE is_email_valid IS NULL OR is_email_valid = 0")
      return rows.to_json
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end

  
  def Core.list_needs_consent()
    emails = CoreConfig.db.execute("SELECT DISTINCT email FROM maintainers WHERE consent_date IS NULL OR  DATE(consent_date) <= DATE('now', '-1 year')")
    return emails.to_json
  end


  def Core.list_bad_emails()
    emails = CoreConfig.db.execute("SELECT DISTINCT email FROM maintainers WHERE 
                                   consent_date IS NULL OR  DATE(consent_date)
                                   <= DATE('now', '-1 year') OR 
                                   is_email_valid IS NULL OR is_email_valid = 0")
    return emails.to_json
  end

  
  def Core.process_sns_notification(payload)
    begin
      sns_message = JSON.parse(payload)
    rescue JSON::ParserError => e
      return [400, "Invalid JSON"]
    end
    
    case sns_message['Type']
    when 'SubscriptionConfirmation'
      # Auto-confirm subscription (optional)
      confirm_url = sns_message['SubscribeURL']
      Thread.new do
        require 'net/http'
        require 'uri'
        uri = URI(confirm_url)
        Net::HTTP.get(uri)
      end
      return [200, "Subscription confirmed"]
      
    when 'Notification'
      begin
        notification = JSON.parse(sns_message['Message'])
      rescue JSON::ParserError => e
        return [400, "Invalid nested JSON"]
      end

      case notification['eventType']
      when 'Bounce'
        Core.handle_bounce(notification)
      when 'Complaint'
        Core.handle_complaint(notification)
      when 'Reject'
        Core.handle_reject(notification)
      when 'RenderingFailure'
        Core.handle_rendering_failure(notification)
      end
      return [200, "Processed"]

    else
      return [400, "Unsupported SNS message type"]
    end
  end

  
  def Core.handle_bounce(notification)
    mail = notification['mail']
    bounce = notification['bounce']
    tags = mail['tags'] || {}
    
    return unless tags['App'] && tags['App'].include?('BioconductorMaintainerValidation')
    
    bounce_type = bounce['bounceType']
    bounce_subtype = bounce['bounceSubType']
    
    bounce['bouncedRecipients'].each do |recipient|
      email = recipient['emailAddress']
      smtp_status = recipient['status']
      diagnostic_code = recipient['diagnosticCode']
      
      CoreConfig.db.execute(
        "UPDATE maintainers
         SET email_status = ?, is_email_valid = 0,
             bounce_type = ?, bounce_subtype = ?,
             smtp_status = ?, diagnostic_code = ?
         WHERE email = ?",
        ["bounced", bounce_type, bounce_subtype, smtp_status, diagnostic_code, email]
      )
    end
  end


  def Core.handle_complaint(notification)
    mail = notification['mail']
    complaint = notification['complaint']
    tags = mail['tags'] || {}
    
    return unless tags['App'] && tags['App'].include?('BioconductorMaintainerValidation')

    complaint['complainedRecipients'].each do |recipient|
      email = recipient['emailAddress']
      
      CoreConfig.db.execute(
        "UPDATE maintainers
         SET email_status = ?, is_email_valid = 0,
             bounce_type = NULL, bounce_subtype = NULL,
             smtp_status = NULL, diagnostic_code = NULL
         WHERE email = ?",
        ["complained", email]
      )
    end
  end

  
  def Core.handle_reject(notification)
    mail = notification['mail']
    reject = notification['reject']
    tags = mail['tags'] || {}

    return unless tags['App'] && tags['App'].include?('BioconductorMaintainerValidation')

    email = mail['destination'].first
    reason = reject['reason'] || "Unknown rejection reason"

    CoreConfig.db.execute(
      "UPDATE maintainers
       SET email_status = ?, is_email_valid = 0,
           bounce_type = ?, bounce_subtype = NULL,
           smtp_status = NULL, diagnostic_code = ?
       WHERE email = ?",
      ["rejected", "reject", reason, email]
    )
  end


  def Core.handle_rendering_failure(notification)
    mail = notification['mail']
    failure = notification['renderingFailure']
    tags = mail['tags'] || {}

    return unless tags['App']&.include?('BioconductorMaintainerValidation')

    email = mail['destination'].first
    error_message = failure['errorMessage']

    CoreConfig.db.execute(
      "UPDATE maintainers
         SET email_status = ?, is_email_valid = 0,
           bounce_type = ?, bounce_subtype = NULL,
           smtp_status = NULL, diagnostic_code = ?
       WHERE email = ?",
      ['rendering_failure', 'rendering_failure', error_message, email]
    )
  end


  def Core.get_filtered_db_dump
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      rows = CoreConfig.db.execute(<<-SQL)
        SELECT 
          package, name, email, consent_date, email_status,
          is_email_valid, last_verification_sent, bounce_type, bounce_subtype, smtp_status, diagnostic_code
        FROM maintainers
      SQL
      return rows
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end

  def Core.check_emails_against_suppression_list
    sesv2 = Core.get_ses_client_v2

    rows = CoreConfig.db.execute(
      "SELECT DISTINCT email
       FROM maintainers
       WHERE (is_email_valid = 1 OR is_email_valid IS NULL)
       AND (consent_date IS NULL OR DATE(consent_date) <= DATE('now', '-1 year'))"
    )

    results = []
    suppressed = {}

    begin
      next_token = nil
      loop do
        resp = sesv2.list_suppressed_destinations(next_token: next_token)

        resp.suppressed_destination_summaries.each do |s|
          suppressed[s.email_address.downcase] = s
        end

        next_token = resp.next_token
        break unless next_token
      end
    rescue Aws::SESV2::Errors::ServiceError => e
      Core.logger.error "Error retrieving SES suppression list: #{e.message}"
      return [{ error: e.message }].to_json
    end

    rows.each do |row|
      email = row[0].to_s
      email_lc = email.downcase

      begin
        sup = suppressed[email_lc]
        next unless sup 

        Core.logger.info "Email #{email} IS on SES suppression list. Reason: #{sup.reason}"

        CoreConfig.db.execute(
          "UPDATE maintainers
           SET email_status = ?,
               is_email_valid = 0,
               bounce_type = ?,
               bounce_subtype = NULL,
               smtp_status = NULL,
               diagnostic_code = ?
           WHERE email = ?",
          ["suppressed", sup.reason, sup.last_update_time.to_s, email]
        )

        results << { email: email, suppressed: true, reason: sup.reason }

      rescue Aws::SESV2::Errors::ServiceError => e
        Core.logger.error "AWS error checking #{email}: #{e.message}"
        results << { email: email, error: e.message }

      rescue => e
        Core.logger.error "Unexpected error processing #{email}: #{e.class} - #{e.message}"
        results << { email: email, error: "unexpected_error" }
      end
    end

    results.to_json
  end

  
  def Core.list_suppression_list()
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      info = CoreConfig.db.execute("SELECT DISTINCT email, name FROM maintainers WHERE email_status = 'suppressed'")
      if info.empty?
        return {awssuppression: false}.to_json
      else
        return {awssuppression: true, data: info}.to_json
      end
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end      
  end
  
  
end

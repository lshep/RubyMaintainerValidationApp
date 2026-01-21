require 'json'
require 'sqlite3'
require 'bcrypt'
require 'securerandom'
require 'aws-sdk-ses'
require 'aws-sdk-sesv2'
require 'date'
require 'logger'
require_relative './core'




  def Core.check_emails_against_suppression_list()
    
    sesv2 = Core.get_ses_client_v2

    rows = CoreConfig.db.execute(
      "SELECT DISTINCT email 
       FROM maintainers
       WHERE (is_email_valid = 1 OR is_email_valid IS NULL)
       AND (consent_date IS NULL OR DATE(consent_date) <= DATE('now', '-1 year'))")

    results = []

    rows.each do |row|
      email = row[0]
      Core.logger.info "Checking suppression list for #{email}"

      begin
        resp = sesv2.get_suppressed_destination(email_address: email)

        if resp && resp.suppressed_destination
          sup = resp.suppressed_destination

          Core.logger.info "Email #{email} IS on SES suppression list. Reason: #{sup.reason}"

          # Update DB and invalidate
          CoreConfig.db.execute(
            "UPDATE maintainers
             SET email_status = ?,
                 is_email_valid = 0,
                 bounce_type = ?,
                 bounce_subtype = NULL,
                 smtp_status = NULL,
                 diagnostic_code = ?
             WHERE email = ?",
            ["suppressed",sup.reason, sup.last_update_time.to_s, email]
          )

          results << { email: email, suppressed: true, reason: sup.reason }
        end
      rescue Aws::SESV2::Errors::NotFoundException
        #Core.logger.info "#{email} not on suppression list"
        #results << { email: email, suppressed: false }
      rescue Aws::SESV2::Errors::ServiceError => e
        Core.logger.error "Error checking #{email}: #{e.message}"
        results << { email: email, error: e.message }
      end
    end

    results.to_json
  end






# get suppression list

  def Core.check_emails_against_suppression_list()
    
    sesv2 = Core.get_ses_client_v2
    
    results = []

    rows = CoreConfig.db.execute(
      "SELECT DISTINCT email 
       FROM maintainers
       WHERE (is_email_valid = 1 OR is_email_valid IS NULL)
       AND (consent_date IS NULL OR DATE(consent_date) <= DATE('now', '-1 year'))")

    suppressed = {}

    next_token = nil
    loop do
      resp = sesv2.list_suppressed_destinations(
        next_token: next_token
      )

      resp.suppressed_destination_summaries.each do |s|
        suppressed[s.email_address.downcase] = s
      end

      next_token = resp.next_token
      break unless next_token
    end

    rows.each do |row|
      email = row[0].downcase
      sup = suppressed[email]
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
    end
    results.to_json
  end

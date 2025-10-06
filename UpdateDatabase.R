args <- commandArgs(trailingOnly = TRUE)

sendEmail <- if (length(args) == 0) {
    FALSE
} else if (tolower(args[1]) %in% c("true", "false")) {
    as.logical(tolower(args[1]))
} else {
    message("Argument given is not a logical: TRUE/FALSE")
    FALSE
}

library(dplyr)
library(stringr)
library(RSQLite)
library(DBI)
library(jsonlite)
library(httr2)

## change for live location
url_base = "http://127.0.0.1:4567"

debug=FALSE

files <- c(
    "https://www.bioconductor.org/packages/release/bioc/VIEWS",
    "https://www.bioconductor.org/packages/devel/bioc/VIEWS",
    "https://www.bioconductor.org/packages/release/data/experiment/VIEWS",
    "https://www.bioconductor.org/packages/devel/data/experiment/VIEWS",
    "https://www.bioconductor.org/packages/release/workflows/VIEWS",
    "https://www.bioconductor.org/packages/devel/workflows/VIEWS",
    "https://www.bioconductor.org/packages/release/data/annotation/VIEWS",
    "https://www.bioconductor.org/packages/devel/data/annotation/VIEWS")



emails_list <- list()

## Helper function: extract (name, email) pairs
##  used chatgpt to debug 
clean_name <- function(name) {
  ## Trim and collapse whitespace
  ## Remove ORCID-like IDs (e.g., 0000-0002-7688-6974)
  name <- str_squish(name)
  name <- gsub("\\b\\d{4}-\\d{4}-\\d{4}-\\d{4}\\b", "", name)
  name <- str_squish(name)
  return(name)
}

extract_name_email <- function(maintainer_string) {
  pattern <- "([^,<]+?)\\s*<([^>]+)>"
  matches <- str_match_all(maintainer_string, pattern)[[1]]
  if (nrow(matches) == 0) {
    return(data.frame(Name=character(0), Email=character(0), stringsAsFactors=FALSE))
  }  
  df <- data.frame(
    Name = sapply(str_trim(matches[, 2]), clean_name),
    Email = str_trim(matches[, 3]),
    stringsAsFactors = FALSE
  ) 
  return(df)
}

for (i in seq_along(files)) {
  temp <- read.dcf(url(files[i]))

  for (j in seq_len(nrow(temp))) {
    pkg_name <- temp[j, "Package"]
    maint_raw <- temp[j, "Maintainer"]

    name_email_df <- extract_name_email(maint_raw)

    if (nrow(name_email_df) > 0) {
      name_email_df$Package <- pkg_name
      emails_list[[length(emails_list) + 1]] <- name_email_df[, c("Package", "Name", "Email")]
    }
  }
}


email_df <- do.call(rbind, emails_list)
email_df$Package <- str_trim(email_df$Package)
email_df$Name    <- str_trim(email_df$Name)
email_df$Email   <- str_trim(email_df$Email)
email_df <- unique(email_df)

## XINA  used and 
## anota2seq  used , 
## BEARscc  had /n
## XVector has special character name
## xcore has special character name
## are there other edge cases? else seems correct

## write.csv(email_df, file = "MaintainerEmailList.csv", row.names=FALSE)

## Now filter only unique emails (to potentially pass to validator)
## email_only <- unique(email_df[,"Email"])
## temp <- lapply(email_only, write, "EmailList.txt", append=TRUE)

## save.image("GetEmailList.RData")




## ------------------------------------------------------------------------------##
##
## Connect to Database
##
## ------------------------------------------------------------------------------## 

con <- dbConnect(RSQLite::SQLite(), "db.sqlite3")


dbExecute(con, "
CREATE TABLE IF NOT EXISTS maintainers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    consent_date DATE,
    pw_hash TEXT,
    email_status TEXT,
    is_email_valid BOOLEAN,
    bounce_type TEXT,
    bounce_subtype TEXT,
    smtp_status TEXT,
    diagnostic_code TEXT,
    UNIQUE(package, email));
")

existing_pairs <- dbGetQuery(con, "SELECT package, email FROM maintainers")

## ------------------------------------------------------------------------------##
##
##  Adding New Entries
##
## ------------------------------------------------------------------------------## 

is_new_pair <- function(pkg, email) {
  !any(existing_pairs$package == pkg & existing_pairs$email == email)
}

new_rows <- email_df[mapply(is_new_pair, email_df$Package, email_df$Email), ]

if(nrow(new_rows) > 0){

    to_insert <- data.frame(
        package = new_rows$Package,
        name = new_rows$Name,
        email = new_rows$Email,
        consent_date = as.character(Sys.Date()),
        pw_hash = NA,
        email_status = "new",
        is_email_valid = TRUE
    )
    
    dbWriteTable(con, "maintainers", to_insert, append = TRUE, row.names = FALSE)
    message("Inserted ", nrow(to_insert), " new rows.")
} else {
    message("No new rows to insert.")
}


## ------------------------------------------------------------------------------##
##
##  Deleting Removed Entries
##
## ------------------------------------------------------------------------------## 

current_pairs <- email_df %>%
  transmute(package = Package, email = Email) %>%
  distinct()

deleted_pairs <- anti_join(existing_pairs, current_pairs, by = c("package", "email"))

if (nrow(deleted_pairs) > 0) {

    if(debug) print(deleted_pairs)
    
    for (i in seq_len(nrow(deleted_pairs))) {
        dbExecute(con, "DELETE FROM maintainers WHERE package = ? AND email = ?",
                  params = list(deleted_pairs$package[i], deleted_pairs$email[i]))
    }
    
    message("Deleted ", nrow(deleted_pairs), " obsolete rows.")
} else {
    message("No rows to delete.")
}

## ------------------------------------------------------------------------------##
##
##  Trigger Email Verification
##
## ------------------------------------------------------------------------------## 

if(sendEmail){

    query <- "
SELECT id, name, email
FROM maintainers
WHERE consent_date IS NULL
  OR DATE(consent_date) <= DATE('now', '-1 year')
"

    stale_consent <- dbGetQuery(con, query)
    
    stale_unique <- stale_consent %>%
        distinct(name, email, .keep_all = TRUE)
    
    if(debug) print(stale_unique)
    
    # Save to JSON
    if (nrow(stale_unique) > 0) {
        json_payload <- toJSON(stale_unique, pretty = TRUE, auto_unbox = TRUE, na = "null")
        email_url <- paste0(url_base, "/send-verification")
        response <- request(email_url) %>%
            req_headers("Content-Type" = "application/json") %>%
            req_body_raw(json_payload) %>%
            req_perform()
        if (resp_status(response) == 200){
            message("Verification request sent successfully")
        }else{
            warning("Failed to send verification request. Status: ", resp_status(response))
        }
    } else {
        message("No stale consent entries found.")
    }
    
}
    
## write sample json for ruby debugging
## write(json_payload, file = "mock_verification.json")

## ------------------------------------------------------------------------------##
##
##  Update Entry for Name Change
##
## ------------------------------------------------------------------------------## 

existing_trio <- dbGetQuery(con, "SELECT package, email, name FROM maintainers")

needs_name_update <- function(pkg, email, name) {
  !any(existing_trio$package == pkg & existing_trio$email == email &
       existing_trio$name == name)
}

name_changed <- merge(email_df, existing_trio, 
                      by.x = c("Package", "Email"), 
                      by.y = c("package", "email"),
                      all.x = FALSE, all.y = FALSE)

name_changed <- name_changed[name_changed$Name != name_changed$name, ]

if (nrow(name_changed) > 0) {
  # Loop through and update names in the database
  for (i in seq_len(nrow(name_changed))) {
    dbExecute(con, "
      UPDATE maintainers
      SET name = ?
      WHERE package = ? AND email = ?;
    ", params = list(name_changed$Name[i],
                     name_changed$Package[i],
                     name_changed$Email[i]))
  }
  message(nrow(name_changed), " name(s) updated.")
} else {
  message("No names need updating.")
}

## Disconnect from database
dbDisconnect(con)

#!/bin/bash
cd /opt/RubyMaintainerValidationApp
export R_LIBS_USER=/home/ubuntu/R/x86_64-pc-linux-gnu-library/4.3
/usr/bin/Rscript UpdateDatabase.R "$@" >> log/UpdateDatabase.log 2>&1

# Import the TCL HTTP Package
package require http

# Get an authentication token
set tURL "https://ti-api.hoplite.io/token"
set tResponse ::http::geturl $tURL -query [::http::formatQuery client_id user@domain.com client_secret XXXXX-XXXX-XXXXX-XXXXX-XXXXXX grant_type=client_credentials -type application/json -method PUT]
set $aToken [::http::data $tResponse]"

# Setup the REST API call
set ip = 128.75.222.116
set iURL = "https://ti-api.hoplite.io/ip/$ip"

# Execute the REST API call
set iToken ::http::geturl $iURL -query [::http::formatQuery Authorization "Bearer $aToken" -type application/json -method GET]
puts "Response [::http::data $iToken]"

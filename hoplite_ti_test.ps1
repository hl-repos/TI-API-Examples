##
## PowerShell Test Harness for the Hoplite Threat Intel API
## Not fully parametereized, illustrative purposes only
##
## @author	acochenour@hopliteindustries.com
## @copyright	2014-2016 Hoplite Industries, Inc.
## @license	
## @version	0.1
## @since	v0.1
##

## Establish the body of the access token request
$body = @{
	client_id='user@domain.com'
	client_secret='API_KEY'
	grant_type='client_credentials'
}
$json = $body | ConvertTo-Json

## Execute the API POST to get a current access token
$tResponse = Invoke-RestMethod 'https://ti-api.hoplite.io/token' -Method POST -Body $json -ContentType 'application/json'
$token = $tResponse.access_token

## Build the correct HTTP header for the API GET request
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer "+$token)

## With the access token and HTTP header in hand, execute the API GET to see if the subject ip, 128.75.222.116, is malicious
$aResponse = Invoke-RestMethod 'https://ti-api.hoplite.io/ip/128.75.222.116' -Method GET -Header $headers -ContentType 'application/json'
Write-Output $aResponse

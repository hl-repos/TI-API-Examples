'''
  hoplite_ti_test.php
  Test harness for for interacting with the Hoplite Threat Intelligence APIs
  Not fully parametereized, illustrative purposes only
 
  @author	acochenour@hopliteindustries.com
  @copyright	2014-2016 Hoplite Industries, Inc.
  @license		
  @version	0.1
  @since	v0.1
'''
import requests
import json
import pprint

'''
  Build the request to obtain an access token
'''
data = {"client_id": "user@domain.com", "client_secret": "XXXX-XXXX-XXXX-XXXXX-XXXXX", "grant_type": "client_credentials"}

'''
  With the raw response in hand, extract the access_token and close the connection
'''
tResponse = requests.post('https://ti-api.hoplite.io/token', data)
json_data = json.loads(tResponse.text)
token = json_data['access_token']

'''
  Using the access token, issue a GET request to determine if the subject ip 128.75.222.116 is in the Hoplite Threat Intel database
'''
aResponse = requests.get('https://ti-api.hoplite.io/ip/128.75.222.116', headers={'Authorization': 'Bearer ' + token})

'''
  Reformat and print the output
'''
json_data = json.loads(aResponse.text)
pp = pprint.PrettyPrinter(indent=4)
pp.pprint(json_data)

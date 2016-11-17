<?php
/**
 * hoplite_ti_test.php
 * Test harness for for interacting with the Hoplite Threat Intelligence APIs
 * Not fully parametereized, illustrative purposes only
 *
 * PHP version 5.5+
 *
 * @author		acochenour@hopliteindustries.com
 * @copyright	2014-2016 Hoplite Industries, Inc.
 * @license		
 * @version		0.1
 * @since		  v0.1
 */

/*
 * Build the request to obtain an access token
 */
$pVars = array(
	'client_id' => 'user@domain.com',
	'client_secret' => 'API_KEY',
	'grant_type' => 'client_credentials'
);

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL,"https://ti-api.hoplite.io/token");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS,$pVars);  //Post Fields
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

/*
 * With the raw response in hand, extract the access_token and close the connection
 */
$tResponse = curl_exec ($ch);
$tResponse = json_decode($tResponse);
$token = $tResponse->access_token;
curl_close ($ch);

/*
 * Using the access token, issue a GET request to determine if the subject ip 128.75.222.116
 * is in the Hoplite Threat ntel database
 * 
 */
$header = array(
		'Authorization: Bearer '.$token
);
$ch = curl_init();
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_URL,"https://ti-api.hoplite.io/ip/128.75.222.116");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$aResponse = curl_exec ($ch);

/*
 * Reformat and print the output
 */
$aResponse = json_decode($aResponse);
print_r($aResponse);
curl_close ($ch);

?>

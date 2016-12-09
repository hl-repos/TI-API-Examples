/* Get an access token using client_id and client_secret */
jQuery.ajax( {
    url: 'https://ti-api.hoplite.io/',
    type: 'POST',
    data: { client_id: 'user@domain.com', client_secret: 'XXXXX-XXXX-XXXXX-XXXXX-XXXXXX', grant_type: 'client_credentials' },
    success: function( response ) {
        // Capture response -> 'access_token', used below
    }
} );

/* Use the access token to check the IP address stored in the 'ip' variable agains the TI API */
jQuery.ajax( {
    url: 'https://ti-api.hoplite.io/ip/' + ip,
    type: 'GET',
    data: { content: 'testing test' },
    beforeSend : function( xhr ) {
        xhr.setRequestHeader( "Authorization", "BEARER " + access_token );
    },
    success: function( response ) {
        // Display the result of the API call
    }
} );

#!/bin/bash
writefile=certbot.pem

baseurl=https://certbot.mycompany.com
echo "Using CertBot API At $baseurl"

read -p "Would you like acme or ca service? " service
echo "Requesting certs from $service"

read -p "Which $service account ID should I use? " accountid
echo "using api base url $baseurl"

certfile=/crypto/automation@user.pem
echo "using TLS client certificate for authentication: $certfile"

#read -s -p "Enter client tls certificate password: " certpass
echo ""

read -p "Enter certificate id to retrieve: " certid
echo "requesting certificate id $certid"

token=$(curl -s --cert  $certfile:$certpass $baseurl/api/authenticate | jq '.token')

if [ -n "$token" ]; then
    #echo "got JWT: $token"
    #curl -s --cert $certfile:$certpass $baseurl/api/acme/accounts/1?token=$token | json_pp
    fullchain=$(curl -s --cert $certfile:$certpass $baseurl/api/$service/accounts/$accountid/certificates/$certid/pem?token=$token)
	printf "%s" "$fullchain" > $writefile

else
    echo "error authenticating to API, aborting"

fi

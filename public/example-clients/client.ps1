# Create an object that can do TLS client authentication to a web service using the local certificate repository
$def = @"
public class ClientCertWebClient : System.Net.WebClient
{
	System.Net.HttpWebRequest request = null;
	System.Security.Cryptography.X509Certificates.X509CertificateCollection certificates = null;

	protected override System.Net.WebRequest GetWebRequest(System.Uri address) {
		request = (System.Net.HttpWebRequest)base.GetWebRequest(address);
		if (certificates != null) {
			request.ClientCertificates.AddRange(certificates);
		}
		return request;
	}

	public void AddCerts(System.Security.Cryptography.X509Certificates.X509Certificate[] certs) {
		if (certificates == null) {
			certificates = new System.Security.Cryptography.X509Certificates.X509CertificateCollection();
		}
		if (request != null) {
			request.ClientCertificates.AddRange(certs);
		}
		certificates.AddRange(certs);
	}
}
"@
Add-Type -TypeDefinition $def

# API information
$baseurl = "https://certbot.mycompany.com/api/"
$service = "acme" # 'acme' or 'ca' type accounts are supported

# Create our authenticated web client
$wc = New-Object ClientCertWebClient

### Certificate Authentication
# Get the certs, first one thumbprint we use for the client...
$certstore = "CurrentUser"
#$certstore = "LocalMachine"
$certs = dir cert:\$certstore\My
$thumbprint = $certs[0].Thumbprint
$cert = Get-Childitem cert:\$certstore\My\$thumbprint 
# Assign the cert we want to auth with to the client
$wc.AddCerts($cert)
$response = $wc.DownloadString($baseurl + "authenticate") | convertFrom-JSON
<#
$username = "" # valid LDAP username
$password = "" # valid LDAP password
### LDAP Authentication
# create a name-value-collection
$nvc = New-Object System.Collections.Specialized.NameValueCollection
$nvc.Add("username", $username);
$nvc.Add("password", $password);
# POST those values to 
$response = [System.Text.Encoding]::UTF8.GetString(
    $wc.UploadValues($baseurl + "authenticate", "post", $nvc)
) | convertFrom-JSON
#
<##>

# Ensure we have a valid json web token for future calls
if (!$response.token) {
    Write-Host "Could not get token from API!"
    Exit(1)
}

# Save our authentication token
$token = "?token=" + $response.token

# Get the list of $SERVICE accounts this user has access to
$response = $wc.DownloadString($baseurl + $service + "/accounts" + $token) | convertFrom-JSON
$accounts = $response.accounts;

#use the first account ID that comes back
$accountid = $accounts[0].id

# get the certificates in that account ID
$response = $wc.DownloadString($baseurl + $service + "/accounts/" + $accountid + "/certificates" + $token) | convertFrom-JSON
$certificates = $response.certificates;

# Use the first cert in that list
$certificateid = $certificates[0].id

# Get all the details we have access to regarding that certificate
$response = $wc.DownloadString($baseurl + $service + "/accounts/" + $accountid + "/certificates/" + $certificateid + $token) | convertFrom-JSON
$certificate = $response.certificate

# Get the PEM and PKCS12 encoded files if we have access
$pem = $wc.DownloadString($baseurl + $service + "/accounts/" + $accountid + "/certificates/" + $certificateid + "/pem" + $token)
$p12 = $wc.DownloadString($baseurl + $service + "/accounts/" + $accountid + "/certificates/" + $certificateid + "/pkcs12" + $token)

# Now we can save the PEM data to a file for the application to use and reload/restart that app
# or we can install/update the PKCS12 certificate in the windows crypto store for use in IIS etc.
# FOSS software tends to prefer PEM cert-chain-key files while .Net and J2SE use crypto stores

<?php

/**
 * CertBot Acme Client & Certificate Authority Manager.
 *
 * PHP version 7
 *
 * Manage and distribute certificates using a Laravel 5.2 RESTful JSON API
 *
 * @category  default
 * @author    Metaclassing <Metaclassing@SecureObscure.com>
 * @copyright 2015-2016 @authors
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace App\Acme;

use App\Acme\Authorization;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Facades\Log;

/**
 * @SWG\Definition(
 *   definition="AcmeAccount",
 *   required={"name", "contact", "zones", "acmeCAurl", "acmeLicense", "authType", "authProvider"},
 * )
 **/
class Account extends Model implements \OwenIt\Auditing\Contracts\Auditable
{
    use SoftDeletes;
    use \OwenIt\Auditing\Auditable;

    protected $table = 'acme_accounts';
    protected $fillable = ['name', 'contact', 'zones', 'acmecaurl', 'acmelicense', 'authtype', 'authprovider', 'authaccount', 'authuser', 'authpass', 'orders'];
    protected $hidden = ['publickey', 'privatekey', 'acmelicense', 'authpass', 'registration', 'deleted_at'];
    /**
     * @SWG\Property(property="id", type="integer", format="int64", description="Unique identifier for the account id")
     * @SWG\Property(property="name", type="string", description="Name of this account")
     * @SWG\Property(property="contact", type="string", description="email address for account contact")
     * @SWG\Property(property="zones", type="string", description="List of zones this account is authorized to issue certificates for")
     * @SWG\Property(property="acmecaurl", type="string", description="Base url of ACME certificate authority")
     * @SWG\Property(property="acmelicense", type="string", description="Full url of ACME certificate authority license agreement")
     * @SWG\Property(property="authtype", type="string", description="supported authentication type http or dns")
     * @SWG\Property(property="authprovider", type="string", description="provider for authtype http path or dns provider")
     * @SWG\Property(property="authaccount", type="string", description="account id for auth providers requiring authentication")
     * @SWG\Property(property="authuser", type="string", description="username for auth providers requiring authentication")
     * @SWG\Property(property="authpass", type="string", description="password for auth providers requiring authentication")
     * @SWG\Property(property="status", type="string", enum={"unregistered", "registered"}, description="status of this account, unregistered or registered")
     * @SWG\Property(property="created_at",type="string",format="date-format",description="Date this interaction was created")
     * @SWG\Property(property="updated_at",type="string",format="date-format",description="Date this interaction was last updated")
     * @SWG\Property(property="deleted_at",type="string",format="date-format",description="Date this interaction was deleted")
     **/
    public $client;
    private $messages;
    private $dnsClient;

    // Relationships
    public function certificates()
    {
        return $this->hasMany(Certificate::class);
    }

    public function log($message = '')
    {
        if ($message) {
            $this->messages[] = $message;
            file_put_contents(storage_path('logs/accountclient.log'),
                                \Metaclassing\Utility::dumperToString($message).PHP_EOL,
                                FILE_APPEND | LOCK_EX
                            );
            Log::info($message);
        }

        return $this->messages;
    }

    public function acmeClientLog()
    {
        return $this->client->log();
    }

    // This sets our RSA key pair for request signing
    public function generateKeys($size = 4096)
    {
        $rsaKeyGen = new \phpseclib\Crypt\RSA();
        $rsaKeyPair = $rsaKeyGen->createKey($size);
        $this->publickey = $rsaKeyPair['publickey'];
        $this->privatekey = $rsaKeyPair['privatekey'];
        $this->status = 'unregistered';
        $this->registration = '';
        $this->save();
    }

    public function postNewReg()
    {
        if ($this->status != 'unregistered') {
            throw new \Exception('Account status is not unregistered, it is '.$this->status);
        }
        // Error handling: make sure our $this->contact is a VALID email address
        $response = $this->signedRequest(
                                        $this->acmecaurl . '/acme/new-acct',
                                        [
//                                            'contact'   => ['mailto:'.$this->contact],
//                                            'termsOfServiceAgreed' => true,
                                            'onlyReturnExisting' => true,
                                        ]
                                    );
        // Make sure there are no error codes coming back from acme ca before marking registration ok
        if (! isset($response['id'])
        || ! $response['id']) {
            throw new \Exception('registration update error, no acme ca registration id recieved in response');
        }
        $this->registration = \Metaclassing\Utility::encodeJson($response);
        $this->status = 'registered';
        $this->save();

        return $response;
    }

    public function postUpdateReg()
    {
        if ($this->status != 'registered') {
            throw new \Exception('account status is not registered, it is '.$this->status);
        }
        if (! \Metaclassing\Utility::isJson($this->registration)) {
            throw new \Exception('error, registration data is not valid json');
        }
        $registration = \Metaclassing\Utility::decodeJson($this->registration);
        $regid = $registration['id'];
        $response = $this->signedRequest(
                                        $this->acmecaurl . '/acme/reg/'.$regid,
                                        [
                                            'resource'  => 'reg',
                                            'contact'   => ['mailto:'.$this->contact],
                                            'agreement' => $this->acmelicense,
                                        ]
                                    );
        if (! $response['id']) {
            dd($response);
            throw new \Exception('registration update error, no acme ca registration id recieved in response');
        }
        $this->registration = \Metaclassing\Utility::encodeJson($response);
        $this->save();

        return $response;
    }

    private function getCsrContent($certificate)
    {
        preg_match('~REQUEST-----(.*)-----END~s', $certificate->request, $matches);

        return trim($this->base64UrlSafeEncode(base64_decode($matches[1])));
    }

    private function parsePemFromBody($body)
    {
        $pem = chunk_split(base64_encode($body), 64, "\n");

        return "-----BEGIN CERTIFICATE-----\n".$pem.'-----END CERTIFICATE-----';
    }

    private function base64UrlSafeEncode($input)
    {
        //return base64_encode($input);
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public function getAcmeChallenge($subject)
    {
        $this->log('beginning challenge for subject '.$subject);
        // Get a challenge request for each one
        $response = $this->signedRequest(
            $this->acmecaurl . '/acme/new-authz',
            [
                'resource'   => 'new-authz',
                'identifier' => [
                                'type'  => 'dns',
                                'value' => $subject,
                                ],
            ]
        );
        $challenge = '';
        foreach ($response['challenges'] as $option) {
            if ($option['type'] == $this->authtype) {
                $challenge = $option;
                break;
            }
        }
        // need better error handling than this
        if (! $challenge) {
            throw new \Exception('No suitable challenges for selected authtype were identified');
        }

        $challenge['subject'] = $subject;
        $challenge['expires'] = $response['expires'];
        $challenge['location'] = $this->client->getLastLocation();
        $this->log('Got challenge token for '.$subject);

        return $challenge;
    }

    public function getDnsClient()
    {
        // Only make a new dns client if we dont already have one
        if (! $this->dnsClient) {
            $this->log('creating new '.$this->authprovider.' dns client');
            if ($this->authprovider == 'cloudflare') {
                $this->dnsClient = new \Metaclassing\CloudflareDNSClient($this->authuser, $this->authpass);
            } elseif ($this->authprovider == 'neustarultradns') {
                $this->dnsClient = new \Metaclassing\NeustarUltradnsClient($this->authaccount, $this->authuser, $this->authpass);
            // Coming soon
            } elseif ($this->authprovider == 'azuredns') {
                //$this->dnsClient = new \Metaclassing\VerisignDNSClient2($this->authaccount, $this->authuser, $this->authpass);
            } else {
                throw new \Exception('unknown or unsupported auth provider '.$this->authprovider);
            }
            $this->log('successfully created new '.$this->authprovider.' dns client');
        }

        return $this->dnsClient;
    }

    public function getAddressByName($domain)
    {
        $nameservers = ['8.8.8.8', '8.8.4.4', '4.2.2.2'];
        $dnsoptions = ['nameservers' => $nameservers];
        $resolver = new \Net_DNS2_Resolver($dnsoptions);
        $response = $resolver->query($domain, 'A');

        return $response->answer[0]->address;
    }

    public function getAuthoritativeNameservers($domain)
    {
        $nameservers = ['8.8.8.8', '8.8.4.4', '4.2.2.2'];
        $dnsoptions = ['nameservers' => $nameservers];
        $topleveldomain = \Metaclassing\Utility::subdomainToDomain($domain);
        $this->log('Trying to identify authoritative nameservers for '.$domain.' in zone '.$topleveldomain);
        try {
            $resolver = new \Net_DNS2_Resolver($dnsoptions);
            $response = $resolver->query($topleveldomain, 'NS');
            $use = [];
            foreach ($response->answer as $answer) {
                $use[] = $this->getAddressByName($answer->nsdname);
            }
            if (count($use)) {
                $nameservers = $use;
            } else {
                throw new \Exception('Answer for usable nameservers is empty');
            }
        } catch (\Exception $e) {
            $this->log('Exception identifying authoritative nameservers for domain, falling back to public resolution: '.$e->getMessage());
        }

        return $nameservers;
    }

    public function cleanupAcmeChallenge($challenge)
    {
        if ($challenge['type'] == 'http-01') {
            return $this->cleanupAcmeChallengeHttp01($challenge);
        }
        if ($challenge['type'] == 'dns-01') {
            return $this->cleanupAcmeChallengeDns01($challenge);
        }
        throw new \Exception('challenge type '.$challenge['type'].' is not currently supported by this tool');
    }

    public function cleanupAcmeChallengeHttp01($challenge)
    {
        $tokenPath = $this->authprovider.'/.well-known/acme-challenge/'.$challenge['token'];
        if (file_exists($tokenPath) && is_file($tokenPath) && is_writable($tokenPath)) {
            $this->log('unlinking http01 authorization file at '.$tokenPath);
            unlink($tokenPath);
            $this->log('unlinked http01 authorization file at '.$tokenPath);
        } else {
            $this->log('FAILED to unlink http01 authorization file at '.$tokenPath);
        }

        return true;
    }

    public function cleanupAcmeChallengeDns01($challenge)
    {
        $dnsclient = $this->getDnsClient();
        $zone = \Metaclassing\Utility::subdomainToDomain($challenge['subject']);
        $this->log('searching zone '.$zone.' for _acme-challenge. TXT records to clean up');

        if ($this->authprovider == 'cloudflare') {
            $namefield = 'name';
            $idfield = 'id';
        } elseif ($this->authprovider == 'verisign2') {
            $namefield = 'owner';
            $idfield = 'resource_record_id';
        } elseif ($this->authprovider == 'neustarultradns') {
            $namefield = 'ownerName';
            $idfield = 'nameWithoutTld';
        } else {
            throw new \Exception('unknown or unsupported auth provider name and id fields '.$this->authprovider);
        }

        $zonerecords = $dnsclient->getRecords($zone, true);

        $this->log('zone '.$zone.' contains '.count($zonerecords).' to check for _acme-challenge. TXT clean up');
        foreach ($zonerecords as $record) {
            if ($record['type'] == 'TXT' && preg_match('/^_acme-challenge\./', $record[$namefield], $hits)) {
                $this->log('located zone record to clean up '.\Metaclassing\Utility::dumperToString($record));
                $dnsclient->delZoneRecord($zone, $record[$idfield]);
            }
        }

        return true;
    }

    public function cleanupAllAcmeChallengeDns01()
    {
        $dnsclient = $this->getDnsClient();
        $zones = \Metaclassing\Utility::stringToArray($this->zones);
        foreach ($zones as $zone) {
            $this->log('searching zone '.$zone.' for _acme-challenge. TXT records to clean up');

            if ($this->authprovider == 'cloudflare') {
                $namefield = 'name';
                $idfield = 'id';
            } elseif ($this->authprovider == 'verisign2') {
                $namefield = 'owner';
                $idfield = 'resource_record_id';
            } elseif ($this->authprovider == 'neustarultradns') {
                $namefield = 'ownerName';
                $idfield = 'nameWithoutTld';
            } else {
                throw new \Exception('unknown or unsupported auth provider name and id fields '.$this->authprovider);
            }

            $zonerecords = $dnsclient->getRecords($zone, true);

            $this->log('zone '.$zone.' contains '.count($zonerecords).' to check for _acme-challenge. TXT clean up');
            foreach ($zonerecords as $record) {
                if ($record['type'] == 'TXT' && preg_match('/^_acme-challenge\./', $record[$namefield], $hits)) {
                    $this->log('located zone record to clean up '.\Metaclassing\Utility::dumperToString($record));
                    $dnsclient->delZoneRecord($zone, $record[$idfield]);
                }
            }
        }

        return true;
    }

    public function sendAcmeSigningRequest($certificate)
    {
        $this->log('sending certificate request to be signed');
        // If we dont already have an acme curl client object, make sure to create one
        if (! $this->client) {
            $this->client = new Client($this->acmecaurl);
        }
        $this->client->getLastLinks();
        // read our CSR but strip off first/last ----- lines -----
        $csr = $this->getCsrContent($certificate);
        // request certificates creation
        $result = $this->signedRequest(
            $this->acmecaurl . '/acme/new-cert',
            [
                'resource' => 'new-cert',
                'csr'      => $csr,
            ]
        );
        if ($this->client->getLastCode() !== 201) {
            throw new \RuntimeException('Invalid response code: '.$this->client->getLastCode().', '.json_encode($result));
        }
        $this->log('certificate signing request sent successfully');

        return true;
    }

    public function waitAcmeSignatureSaveCertificate($certificate)
    {
        $this->log('waiting for signature and certificate');
        $location = $this->client->getLastLocation();
        // waiting loop
        $certificates = [];
        while (1) {
            $this->client->getLastLinks();

            $result = $this->client->get($location);
            //$result = $this->signedRequest($location, []);

            if ($this->client->getLastCode() == 202) {
                $this->log('certificate generation pending, sleeping 1 second');
                sleep(1);
            } elseif ($this->client->getLastCode() == 200) {
                $this->log('got certificate! YAY!');
                $certificates[] = $this->parsePemFromBody($result);

                foreach ($this->client->getLastLinks() as $link) {
                    $this->log('Requesting chained cert at '.$link);

                    $result = $this->client->get($link);
                    //$result = $this->signedRequest($link, []);

                    $certificates[] = $this->parsePemFromBody($result);
                }
                break;
            } else {
                throw new \RuntimeException('Could not get certificate: HTTP code '.$this->client->getLastCode());
            }
        }
        if (empty($certificates)) {
            throw new \RuntimeException('No certificates generated');
        }

        $this->log('certificate signing complete, saving results');
        $certificate->certificate = array_shift($certificates);
        $certificate->chain = implode("\n", $certificates);
        $certificate->updateExpirationDate();
        $certificate->status = 'signed';
        $certificate->save();

        return true;
    }

    public function makeAuthzForOrder($order)
    {
        $orderAuthorizations = $order->authorizations;

        // Loop through all the authz urls and get the authz information to create our acme_authorization objects...
        foreach($orderAuthorizations as $authorizationUrl) {
            // pull the latest challenge info from acme ca
            $challenge = $this->signedRequest($authorizationUrl, false);

            $subject = $challenge['identifier']['value'];
            // or throw an exception

            $key = [
                    'order_id' => $order->id,
                    'identifier' => $subject,
                   ];

            // Get the existing expired or create a new authz with the account id and subject
            $authz = Authorization::firstOrNew($key);

            // TODO: add order_id to authorizations table so we can track that...
            // $authz->order_id = $order->id;

            // save it to our new or existing challenge
            $authz->order_id = $order->id;
            $authz->challenge = $challenge;
            $authz->status = $challenge['status'];
            $authz->expires = $challenge['expires'];
            $authz->save();
        }
    }

    public function dumb()
    {
        // Loop through the authorizations in the order and get their stuff
        foreach ($subjects as $subject) {
            // Find non-expired authorizations that are pending or valid for our subject if they exist
            $currentAuthz = Authorization::where('account_id', $this->id)
                                         ->where('identifier', $subject)
                                         ->whereDate('expires', '>', \Carbon\Carbon::today()->toDateString())
                                         ->whereIn('status', ['pending', 'valid'])
                                         ->pluck('id');
            // If there are no current authz, make a new one
            if (! count($currentAuthz)) {
                $this->log('no current authorization found for subject '.$subject.' so creating/updating one');

                $key = [
                        'account_id' => $this->id,
                        'identifier' => $subject,
                       ];
                // Get the existing expired or create a new authz with the account id and subject
                $authz = Authorization::firstOrNew($key);

                // Get the new ACME challenge for this authorization
                $challenge = $this->getAcmeChallenge($subject);
                $authz->challenge = $challenge;
                $authz->status = $challenge['status'];
                // wtf 5.5...
                $authz->expires = $challenge['expires'];
                $authz->save();

                $this->log('authz created/updated for subject '.$subject.' with id '.$authz->id);
            // Else log something for me to use for troubleshooting
            } else {
                $this->log('found '.count($currentAuthz).' current authorizations for subject '.$subject.' with ids '.json_encode($currentAuthz));
            }
        }

        return true;
    }

    public function solvePendingAuthzForCertificate($certificate)
    {
        $subjects = $certificate->subjects;

        // Get all pending authz that need to be solved before requesting a signed certificate
        $unsolvedAuthz = Authorization::where('account_id', $this->id)
                                      ->whereIn('identifier', $subjects)
                                      ->whereDate('expires', '>', \Carbon\Carbon::today()->toDateString())
                                      ->where('status', 'pending')
                                      ->get();

        // Put the authorization solving in a try catch block for error handling
        try {
            // First try to build responses to solve each challenge
            foreach ($unsolvedAuthz as $authz) {
                $this->log('building authz response id '.$authz->id);
                $this->buildAcmeResponse($authz->challenge);
            }
            // Then check the acme response to each challenge
            foreach ($unsolvedAuthz as $authz) {
                $this->log('checking authz response id '.$authz->id);
                // Save the payload temporarily as we use it in the next step
                $authz->response = $this->checkAcmeResponse($authz->challenge);
            }
            // Then respond to each challenge with the CA
            foreach ($unsolvedAuthz as $authz) {
                $this->log('responding to authz id '.$authz->id);
                $this->respondAcmeChallenge($authz);
            }
            // if we hit any snags, just log it so it can get resolved
        } catch (\Exception $e) {
            // Always run the cleanup afterwards
            $this->log('caught exception while solving authz '.$e->getMessage());
            $this->log($e->getTraceAsString());
        } finally {
            foreach ($unsolvedAuthz as $authz) {
                $this->cleanupAcmeChallenge($authz->challenge);
            }
        }

        return true;
    }

    public function validateAllAuthzForCertificate($certificate)
    {
        $subjects = $certificate->subjects;

        // Get all non-expired authz for our account subjects
        $allAuthz = Authorization::where('account_id', $this->id)
                                 ->whereIn('identifier', $subjects)
                                 ->whereDate('expires', '>', \Carbon\Carbon::today()->toDateString())
                                 ->get();
        $this->log('checking acme authorization challenge status for '.count($subjects).' subjects and '.count($allAuthz).' authz');
        if (count($subjects) != count($allAuthz)) {
            $this->log('error validing challenges, mismatch of authz and subjects');
            throw new \Exception('Error checking acme authorization challenges, number of subjects does not match number of authz!');
        }
        // Make sure they are all VALID, if we have any authz not valid we can not request a signed cert
        foreach ($allAuthz as $authz) {
            $this->log('acme authorization challenge id '.$authz->id.' for identifier '.$authz->identifier.' is '.$authz->status);
            if ($authz->status != 'valid') {
                throw new \Exception('Error signing certificate, unsolved acme authorization challenge id '.$authz->id);
            }
        }
        $this->log('all acme authorization challenges are valid');

        return true;
    }

    public function subjectToIdentifier($subject)
    {
        $identifier = new \stdClass();
        $identifier->type = 'dns';
        $identifier->value = $subject;
        return $identifier;
    }

    public function certificateToIdentifiers($certificate)
    {
        $identifiers = [];
        $subjects = $certificate->subjects;
        foreach($subjects as $subject) {
            $identifiers[] = $this->subjectToIdentifier($subject);
        }
        return $identifiers;
    }

    public function getOrder($certificate)
    {
        // TODO: Check to see if we have an existing order for this certificate thats VALID and not expired or failed or something...

        // ASSUME we dont have any existing orders that we would have returned before now.

        // convert our certificate to its required order identifiers array of objects.
        $identifiers = $this->certificateToIdentifiers($certificate);

        $this->log('no current orders found for account id '.$this->id.' for certificate '.$certificate->id.' so creating one');

        // POST for new order
        $response = $this->signedRequest(
            $this->acmecaurl . '/acme/new-order',
            [
                'resource'      => 'new-order',
                'identifiers'   => $identifiers,
            ]
            );

        // TODO: handle some failureZ!

//dd($response);
        $order = new Order();
        $order->certificate_id = $certificate->id;
        $order->status = $response['status'];
        $order->identifiers = $response['identifiers'];
        $order->authorizationUrls = $response['authorizations'];
        $order->notBefore = $response['notBefore'];
        $order->notAfter = $response['notAfter'];
        $order->save();

        return $order;
    }

    // Next version of signCertificate, will add support for tracking authorizations and speeding up the signing process
    public function signCertificate($certificate)
    {
        $this->log('beginning NEW signing process for certificate id '.$certificate->id);

        // Certs must have a valid signing request to begin
        if (! $certificate->request) {
            throw new \Exception('Certificate signing request is empty, did you generate a csr first?');
        }

        // Begin cert issuance process by sending a POST request to the newOrder resource:

        // Submit order for certificate
        //$this->submitOrderForCertificate($certificate);

        // Ensure authorizations exist for each subject in the certificate
        $this->makeAuthzForCertificate($certificate);

        // Solve any pending authorization challenges for each subject in the certificate
        $this->solvePendingAuthzForCertificate($certificate);

        // Validate all authorization challenges are valid for each subject in the certificate
        $this->validateAllAuthzForCertificate($certificate);

        // Submit our certificate signing request to the authority
        $this->sendAcmeSigningRequest($certificate);

        // Wait loop for a signed response to our request, or throw an exception to why it failed
        $this->waitAcmeSignatureSaveCertificate($certificate);

        return true;
    }

    // capculate key authorization from token
    public function calculateKeyAuthorizationFromToken($token)
    {
        // start with the JWK part of our acme header
        $header = $this->requestHeader()['jwk'];
        // calculate the sha256 hash of the jwk header
        $hash = hash('sha256', json_encode($header), true);
        // url-safe base64 encode the hash
        $hash64 = $this->base64UrlSafeEncode($hash);
        // calculate the token.urlsafeb64jwkhash
        $payload = $token.'.'.$hash64;
        // now hash it all again with sha256
        $keyauth = hash('sha256', $payload, true);
        // url-safe base64 encode the keyauth
        $keyauth64 = $this->base64UrlSafeEncode($keyauth);
        // and thats what we put in the flat file or dns record...
        return $keyauth64;
    }

    public function getJwk()
    {
        // Load our key pair and grab the raw key information
        $rsaPrivateKey = new \phpseclib\Crypt\RSA();
        $rsaPrivateKey->loadKey($this->privatekey);
        $rawPublicKey = $rsaPrivateKey->getPublicKey(\phpseclib\Crypt\RSA::PUBLIC_FORMAT_RAW);
        $modulus = $this->base64UrlSafeEncode($rawPublicKey['n']->toBytes());
        $exponent = $this->base64UrlSafeEncode($rawPublicKey['e']->toBytes());
        /* Private key detail information lookup:
                n - modulus
                e - publicExponent
                d - privateExponent
                p - prime1
                q - prime2
        */
        $jwk = [
               // somehow this precise key order matters
               'e'   => $exponent,
               'kty' => 'RSA',
               'n'   => $modulus,
               ];
        return $jwk;
    }

    public function requestHeader($sendKid)
    {
        echo 'sendkid: '.$sendKid.PHP_EOL;
        $header = [
                'alg' => 'RS256',
                ];
        if ($sendKid) {
                $header['kid'] = $this->acmecaurl . '/acme/acct/' . $this->acme_account_id;
        } else {
                $header['jwk'] = $this->getJwk();
        }

        return $header;
    }

    public function signedRequest($uri, $payload)
    {
        // If we dont already have an acme curl client object, make sure to create one
        if (! $this->client) {
            $this->client = new Client($this->acmecaurl);
        }
        // Load our key pair and grab the raw key information
        $rsaPrivateKey = new \phpseclib\Crypt\RSA();
        $rsaPrivateKey->loadKey($this->privatekey);

        // by default in acmev2 send the KID
        $sendKid = true;
        // unless we are posting to new-account then DONT
        if ($uri == $this->acmecaurl . '/acme/new-acct') {
            // and use the other JWK instead
            $sendKid = false;
        }
        $header = $this->requestHeader($sendKid);

        $protected = $header;
        $protected['nonce'] = $this->client->getLastNonce();
        $protected['url'] = $uri;

        if ($payload === false) {
            $payload64 = '';
        } else {
            $payload64 = $this->base64UrlSafeEncode(str_replace('\\/', '/', json_encode($payload)));
        }
        $protected64 = $this->base64UrlSafeEncode(json_encode($protected));
        $plaintext = $protected64.'.'.$payload64;
        $rsaPrivateKey->setHash('sha256');
        $rsaPrivateKey->setMGFHash('sha256');
        $rsaPrivateKey->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PKCS1);
        $signed = $rsaPrivateKey->sign($plaintext);
        $signed64 = $this->base64UrlSafeEncode($signed);
        $data = [
                //'header'    => $header,
                'protected' => $protected64,
                'payload'   => $payload64,
                'signature' => $signed64,
            ];

        $original = [
            'protected' => $protected,
            'payload' => $payload,
        ];

        return $this->client->post($uri, json_encode($data), json_encode($original));
    }
}

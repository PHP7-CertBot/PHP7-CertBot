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
    protected $fillable = ['name', 'contact', 'zones', 'acmecaurl', 'acmelicense', 'authtype', 'authprovider', 'authaccount', 'authuser', 'authpass'];
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
    private $client;
    private $messages;
    private $dnsClient;

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

    public function certificates()
    {
        return $this->hasMany(Certificate::class);
    }

    public function postNewReg()
    {
        if ($this->status != 'unregistered') {
            throw new \Exception('Account status is not unregistered, it is '.$this->status);
        }
        // Error handling: make sure our $this->contact is a VALID email address
        $response = $this->signedRequest(
                                        '/acme/new-reg',
                                        [
                                            'resource'  => 'new-reg',
                                            'contact'   => ['mailto:'.$this->contact],
                                            'agreement' => $this->acmelicense,
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
                                        '/acme/reg/'.$regid,
                                        [
                                            'resource'  => 'reg',
                                            'contact'   => ['mailto:'.$this->contact],
                                            'agreement' => $this->acmelicense,
                                        ]
                                    );
        if (! $response['id']) {
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
            '/acme/new-authz',
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
            } elseif ($this->authprovider == 'verisign2') {
                $this->dnsClient = new \Metaclassing\VerisignDNSClient2($this->authaccount, $this->authuser, $this->authpass);
            } elseif ($this->authprovider == 'neustarultradns') {
                $this->dnsClient = new \Metaclassing\NeustarUltradnsClient($this->authaccount, $this->authuser, $this->authpass);
            } else {
                throw new \Exception('unknown or unsupported auth provider '.$this->authprovider);
            }
            $this->log('successfully created new '.$this->authprovider.' dns client');
        }

        return $this->dnsClient;
    }

    public function buildAcmeResponse($challenge)
    {
        if ($challenge['type'] == 'http-01') {
            return $this->buildAcmeResponseHttp01($challenge);
        }
        if ($challenge['type'] == 'dns-01') {
            return $this->buildAcmeResponseDns01($challenge);
        }
        throw new \Exception('challenge type '.$challenge['type'].' is not currently supported by this tool');
    }

    public function buildAcmeResponseHttp01($challenge)
    {
        // apprently we only need the JWK section of the header
        $header = $this->requestHeader()['jwk'];

        $hash = hash('sha256', json_encode($header), true);
        $hash64 = $this->base64UrlSafeEncode($hash);
        $payload = $challenge['token'].'.'.$hash64;

        // temporary HTTP test because we can
        $tokenPath = $this->authprovider.'/.well-known/acme-challenge/'.$challenge['token'];
        file_put_contents($tokenPath, $payload);
        chmod($tokenPath, 0644);
        $this->log('put challenge '.$payload.' at '.$tokenPath);

        return $payload;
    }

    public function buildAcmeResponseDns01($challenge)
    {
        // we only need the JWK section of the header
        $header = $this->requestHeader()['jwk'];

        $hash = hash('sha256', json_encode($header), true);
        $hash64 = $this->base64UrlSafeEncode($hash);
        $payload = $challenge['token'].'.'.$hash64;

        $keyauth = hash('sha256', $payload, true);
        $keyauth64 = $this->base64UrlSafeEncode($keyauth);

        $zone = \Metaclassing\Utility::subdomainToDomain($challenge['subject']);
        $record = '_acme-challenge.'.$challenge['subject'];
        $type = 'TXT';

        // gets the correct DNS client for our auth providers
        $dnsclient = $this->getDnsClient();

        $this->log('calling dnsClient->addZoneRecord('.$zone.', '.$type.', '.$record.', '.$keyauth64.')');
        try {
            $response = $dnsclient->addZoneRecord($zone, $type, $record, $keyauth64);
            $this->log($response);
        } catch (\Exception $e) {
            $this->log('Exception from DNS client: '.$e->getMessage());
            //$this->log($dnsclient->logs());
        }

        return $payload;
    }

    public function checkAcmeResponse($challenge)
    {
        if ($challenge['type'] == 'http-01') {
            return $this->checkAcmeResponseHttp01($challenge);
        }
        if ($challenge['type'] == 'dns-01') {
            return $this->checkAcmeResponseDns01($challenge);
        }
        throw new \Exception('challenge type '.$challenge['type'].' is not currently supported by this tool');
    }

    public function checkAcmeResponseHttp01($challenge)
    {
        // apprently we only need the JWK section of the header
        $header = $this->requestHeader()['jwk'];

        $hash = hash('sha256', json_encode($header), true);
        $hash64 = $this->base64UrlSafeEncode($hash);
        $payload = $challenge['token'].'.'.$hash64;

        // temporary HTTP test because we can
        $tokenURL = 'http://'.$challenge['subject'].'/.well-known/acme-challenge/'.$challenge['token'];
        $response = file_get_contents($tokenURL);
        if ($payload != $response) {
            throw new \Exception('Unable to validate Acme challenge, expected payload '.$payload.' but recieved '.$response);
        }
        $this->log('validated '.$payload.' at '.$tokenURL);

        return $payload;
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

    public function checkAcmeResponseDns01($challenge)
    {
        // we only need the JWK section of the header
        $header = $this->requestHeader()['jwk'];

        $hash = hash('sha256', json_encode($header), true);
        $hash64 = $this->base64UrlSafeEncode($hash);
        $payload = $challenge['token'].'.'.$hash64;

        $keyauth = hash('sha256', $payload, true);
        $keyauth64 = $this->base64UrlSafeEncode($keyauth);

        $record = '_acme-challenge.'.$challenge['subject'];

        // I am forcing the use of public resolvers as the OS itself may use internal resolvers with overlapping namespaces
        $nameservers = $this->getAuthoritativeNameservers($challenge['subject']);
        $this->log('I will attempt to resolve DNS challenges using '.implode(', ', $nameservers));
        $dnsoptions = ['nameservers' => $nameservers];
        $startwait = \Metaclassing\Utility::microtimeTicks();
        // Loop until we get a valid response, or throw exception if we run out of time
        while (true) {
            $this->log('waiting for dns to propogate. Checking record '.$record.' for value '.$keyauth64);
            try {
                $resolver = new \Net_DNS2_Resolver($dnsoptions);
                $response = $resolver->query($record, 'TXT');
                $this->log('Resolver returned the following answers: '.\Metaclassing\Utility::dumperToString($response->answer));
                // The correct txt record must be the FIRST & only TXT record for our _acme-challenge name
                if ($response->answer[0]->text[0] == $keyauth64) {
                    sleep(3);
                    break;
                } else {
                    throw new \Exception('Unable to validate Acme challenge, expected payload '.$keyauth64.' but recieved '.$response->answer[0]->text[0]);
                }
            } catch (\Exception $e) {
                $this->log('DNS resolution exception: '.$e->getMessage());
            }
            // Handle if we run out of time waiting for DNS to update
            if (\Metaclassing\Utility::microtimeTicks() - $startwait > 180) {
                throw new \Exception('Unable to validate Acme challenge, maximum DNS wait time exceeded');
            }
            // Wait a couple seconds and try again
            sleep(3);
        }
        $this->log('validated '.$keyauth64.' at '.$record);

        return $payload;
    }

    public function respondAcmeChallenge($authz)
    {
        $challenge = $authz->challenge;
        $response = $authz->response;

        // send request to challenge
        $result = $this->signedRequest(
            $challenge['uri'],
            [
                'resource'         => 'challenge',
                'type'             => $challenge['type'],
                'keyAuthorization' => $response,
                'token'            => $challenge['token'],
            ]
        );
        $this->log('sent challenge response, waiting for reply');

        // waiting loop
        $errors = 0;
        $maxerrors = 3;
        do {
            if (empty($result['status']) || $result['status'] == 'invalid') {
                $errors++;
                $this->log('Verification error '.$errors.'/'.$maxerrors.' with json '.json_encode($result).' sleeping 5s');
                sleep(5);
                if ($errors > $maxerrors) {
                    $this->log('Maximum verification errors reached '.$errors.'/'.$maxerrors.' with json '.json_encode($result).' sleeping 5s');
                    throw new \RuntimeException('Maximum verification errors reached, verification failed with error: '.json_encode($result));
                }
            }
            $ended = ! ($result['status'] === 'pending');
            if (! $ended) {
                $this->log('Verification pending, sleeping 1s');
                sleep(1);
            }
            $result = $this->client->get($challenge['location']);
            //dd($result);
        } while (! $ended);
        $this->log('challenge verification 2 successful');
        // Clean up the authz object before saving it
        unset($authz->response);
        // Save the outcome of our challenge response
        $authz->status = $result['status'];
        $authz->expires = $result['expires'];
        $authz->save();

        return true;
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
            '/acme/new-cert',
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

            if ($this->client->getLastCode() == 202) {
                $this->log('certificate generation pending, sleeping 1 second');
                sleep(1);
            } elseif ($this->client->getLastCode() == 200) {
                $this->log('got certificate! YAY!');
                $certificates[] = $this->parsePemFromBody($result);

                foreach ($this->client->getLastLinks() as $link) {
                    $this->log('Requesting chained cert at '.$link);
                    $result = $this->client->get($link);
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

    public function makeAuthzForCertificate($certificate)
    {
        $subjects = $certificate->subjects;

        // Loop through the subjects in this cert and ensure we have an authorization object for them
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

    // Next version of signCertificate, will add support for tracking authorizations and speeding up the signing process
    public function signCertificate($certificate)
    {
        $this->log('beginning NEW signing process for certificate id '.$certificate->id);

        // Certs must have a valid signing request to begin
        if (! $certificate->request) {
            throw new \Exception('Certificate signing request is empty, did you generate a csr first?');
        }

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

    public function requestHeader()
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
        $header = [
                'alg' => 'RS256',
                'jwk' => [
                            // somehow this precise key order matters
                            'e'   => $exponent,
                            'kty' => 'RSA',
                            'n'   => $modulus,
                        ],
                ];

        return $header;
    }

    public function signedRequest($uri, array $payload)
    {
        // If we dont already have an acme curl client object, make sure to create one
        if (! $this->client) {
            $this->client = new Client($this->acmecaurl);
        }
        // Load our key pair and grab the raw key information
        $rsaPrivateKey = new \phpseclib\Crypt\RSA();
        $rsaPrivateKey->loadKey($this->privatekey);
        $header = $this->requestHeader();
        $protected = $header;
        $protected['nonce'] = $this->client->getLastNonce();
        $payload64 = $this->base64UrlSafeEncode(str_replace('\\/', '/', json_encode($payload)));
        $protected64 = $this->base64UrlSafeEncode(json_encode($protected));
        $plaintext = $protected64.'.'.$payload64;
        $rsaPrivateKey->setHash('sha256');
        $rsaPrivateKey->setMGFHash('sha256');
        $rsaPrivateKey->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PKCS1);
        $signed = $rsaPrivateKey->sign($plaintext);
        $signed64 = $this->base64UrlSafeEncode($signed);
        $data = [
                'header'    => $header,
                'protected' => $protected64,
                'payload'   => $payload64,
                'signature' => $signed64,
            ];

        return $this->client->post($uri, json_encode($data));
    }
}

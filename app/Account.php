<?php

namespace App;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Account extends Model
{
    use SoftDeletes;
    protected $fillable = ['name', 'contact', 'zones', 'authtype', 'authprovider', 'authuser', 'authpass'];

    private $license = 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf';

    private $client;
    private $messages;

    public function log($message = '')
    {
        if ($message) {
            $this->messages[] = $message;
            file_put_contents(storage_path('logs/accountclient.log'),
                                \metaclassing\Utility::dumperToString($message),
                                FILE_APPEND | LOCK_EX
                            );
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
                                            'agreement' => $this->license,
                                        ]
                                    );
        // Make sure there are no error codes coming back from acme ca before marking registration ok
        if (! $response['id']) {
            throw new \Exception('registration update error, no acme ca registration id recieved in response');
        }
        $this->registration = \metaclassing\Utility::encodeJson($response);
        $this->status = 'registered';
        $this->save();

        return $response;
    }

    public function postUpdateReg()
    {
        if ($this->status != 'registered') {
            throw new \Exception('account status is not registered, it is '.$this->status);
        }
        if (! \metaclassing\Utility::isJson($this->registration)) {
            throw new \Exception('error, registration data is not valid json');
        }
        $registration = \metaclassing\Utility::decodeJson($this->registration);
        $regid = $registration['id'];
        $response = $this->signedRequest(
                                        '/acme/reg/'.$regid,
                                        [
                                            'resource'  => 'reg',
                                            'contact'   => ['mailto:'.$this->contact],
                                            'agreement' => $this->license,
                                        ]
                                    );
        if (! $response['id']) {
            throw new \Exception('registration update error, no acme ca registration id recieved in response');
        }
        $this->registration = \metaclassing\Utility::encodeJson($response);
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

    private function base64UrlSafeDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }

    public function getAcmeChallenge($domain)
    {
        $this->log('beginning challenge for domain '.$domain);
        // Get a challenge request for each one
        $response = $this->signedRequest(
            '/acme/new-authz',
            [
                'resource'   => 'new-authz',
                'identifier' => [
                                'type'  => 'dns',
                                'value' => $domain,
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

        $challenge['domain'] = $domain;
        $challenge['location'] = $this->client->getLastLocation();
        $this->log('Got challenge token for '.$domain);

        return $challenge;
    }

    public function getDnsClient()
    {
        // connect to our dns client
        if ($this->authprovider == 'cloudflare') {
            $this->log('creating new cloudflare dns client');
            $dnsclient = new \metaclassing\CloudflareDNSClient($this->authuser, $this->authpass);
        } elseif ($this->authprovider == 'verisign') {
            $this->log('creating new verisign dns client');
            $dnsclient = new \metaclassing\VerisignDNSClient($this->authuser, $this->authpass);
        } else {
            throw new \Exception('unknown or unsupported auth provider '.$this->authprovider);
        }

        return $dnsclient;
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

        $zone = \metaclassing\Utility::subdomainToDomain($challenge['domain']);
        $record = '_acme-challenge.'.$challenge['domain'];
        $type = 'TXT';

        // gets the correct DNS client for our auth providers
        $dnsclient = $this->getDnsClient();

        $this->log("calling dnsClient->addZoneRecord({$zone}, {$type}, {$record}, {$keyauth64})");
        $response = $dnsclient->addZoneRecord($zone, $type, $record, $keyauth64);
        $this->log($response);

        return $payload;
    }

    public function respondAcmeChallenge($challenge, $response)
    {
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
        $this->log('sent challenge response, waiting for reply ');

        // waiting loop
        do {
            if (empty($result['status']) || $result['status'] == 'invalid') {
                throw new \RuntimeException('Verification failed with error: '.json_encode($result));
            }
            $ended = ! ($result['status'] === 'pending');
            if (! $ended) {
                $this->log('Verification pending, sleeping 1s');
                sleep(1);
            }
            $result = $this->client->get($challenge['location']);
        } while (! $ended);
        $this->log('challenge verification successful');

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
        @unlink($tokenPath);

        return true;
    }

    public function cleanupAcmeChallengeDns01($challenge)
    {
        $dnsclient = $this->getDnsClient();
        $zone = \metaclassing\Utility::subdomainToDomain($challenge['domain']);
        $this->log("searching zone {$zone} for _acme-challenge. TXT records to clean up");

        if ($this->authprovider == 'cloudflare') {
            $namefield = 'name';
            $idfield = 'id';
        } elseif ($this->authprovider == 'verisign') {
            $namefield = 'owner';
            $idfield = 'resourceRecordId';
        } else {
            throw new \Exception('unknown or unsupported auth provider name and id fields '.$this->authprovider);
        }

        $zonerecords = $dnsclient->getRecords($zone);
        foreach ($zonerecords as $record) {
            if ($record['type'] == 'TXT' && preg_match('/^_acme-challenge\./', $record[$namefield], $hits)) {
                $this->log('located zone record to clean up '.\metaclassing\Utility::dumperToString($record));
                $dnsclient->delZoneRecord($zone, $record[$idfield]);
            }
        }

        return true;
    }

    public function sendAcmeSigningRequest($certificate)
    {
        $this->log('sending certificate request to be signed');
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
                    $this->log("Requesting chained cert at $link");
                    $result = $this->client->get($link);
                    $certificates[] = $this->parsePemFromBody($result);
                }
                break;
            } else {
                throw new \RuntimeException("Can't get certificate: HTTP code ".$this->client->getLastCode());
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

    public function signCertificate($certificate)
    {
        $this->log('beginning signing process for certificate id '.$certificate->id);

        $domains = $certificate->domainsArray();
        $challenges = [];
        $responses = [];

        foreach ($domains as $domain) {
            $challenges[$domain] = $this->getAcmeChallenge($domain);
        }

        foreach ($domains as $domain) {
            $responses[$domain] = $this->buildAcmeResponse($challenges[$domain]);
        }
        $this->log('all challenge responses calculated, waiting 15 seconds for dns to propagate');
        sleep(15);

        foreach ($domains as $domain) {
            $success = $this->respondAcmeChallenge($challenges[$domain], $responses[$domain]);
        }

        foreach ($domains as $domain) {
            $success = $this->cleanupAcmeChallenge($challenges[$domain]);
        }
        $this->log('all challenges completed successfully');
        $success = $this->sendAcmeSigningRequest($certificate);
        $success = $this->waitAcmeSignatureSaveCertificate($certificate);

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
            $this->client = new ACMEClient();
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

    // helper for cascade delete of children
/*
    protected static function boot() {
        parent::boot();
        static::deleting(function($Account) {
            foreach ($Account->certificates()->get() as $certificate) {
                $certificate->delete();
            }
        });
    }
/**/
}

























class ACMEClient
{
    private $lastCode;
    private $lastHeader;
    private $base;

    // Production CA
    const ACME_CA_URL = 'https://acme-v01.api.letsencrypt.org';

    // Test CA
//	const ACME_CA_URL = 'https://acme-staging.api.letsencrypt.org';
    public function __construct($base = self::ACME_CA_URL)
    {
        $this->base = $base;
    }

    public function log($message)
    {
        $acmelogfile = storage_path('logs/acmeclient.log');
        file_put_contents($acmelogfile,
                            \metaclassing\Utility::dumperToString($message),
                            FILE_APPEND | LOCK_EX
                        );
    }

    private function curl($method, $url, $data = null)
    {
        $headers = ['Accept: application/json', 'Content-Type: application/json'];
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, preg_match('~^http~', $url) ? $url : $this->base.$url);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);

        // DO NOT DO THAT!
        // curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, false);
        // curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);

        switch ($method) {
            case 'GET':
                break;
            case 'POST':
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
                break;
        }

        $response = curl_exec($handle);

        $this->log(
                    [
                        'method'      => $method,
                        'url'         => $url,
                        'headers'     => $headers,
                        'data'        => $data,
                        'response'    => $response,
                    ]
                );

        if (curl_errno($handle)) {
            throw new \RuntimeException('Curl: '.curl_error($handle));
        }

        $header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);

        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        $this->lastHeader = $header;
        $this->lastCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);

        $data = json_decode($body, true);

        return $data === null ? $body : $data;
    }

    public function post($url, $data)
    {
        return $this->curl('POST', $url, $data);
    }

    public function get($url)
    {
        return $this->curl('GET', $url);
    }

    public function getLastNonce()
    {
        if (preg_match('~Replay\-Nonce: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }

        $this->curl('GET', '/directory');

        return $this->getLastNonce();
    }

    public function getLastLocation()
    {
        if (preg_match('~Location: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }
    }

    public function getLastCode()
    {
        return $this->lastCode;
    }

    public function getLastLinks()
    {
        preg_match_all('~Link: <(.+)>;rel="up"~', $this->lastHeader, $matches);

        return $matches[1];
    }
}

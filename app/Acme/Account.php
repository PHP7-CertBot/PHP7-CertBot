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
    private $dnsClient;

    // Relationships
    public function certificates()
    {
        return $this->hasMany(Certificate::class);
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
                                            //'contact'   => ['mailto:'.$this->contact],
                                            //'termsOfServiceAgreed' => true,
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

    public function getDnsClient()
    {
        // Only make a new dns client if we dont already have one
        if (! $this->dnsClient) {
            \App\Utility::log('creating new '.$this->authprovider.' dns client');
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
            \App\Utility::log('successfully created new '.$this->authprovider.' dns client');
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
        \App\Utility::log('Trying to identify authoritative nameservers for '.$domain.' in zone '.$topleveldomain);
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
            \App\Utility::log('Exception identifying authoritative nameservers for domain, falling back to public resolution: '.$e->getMessage());
        }

        return $nameservers;
    }

    public function cleanupAllAcmeChallengeDns01()
    {
        $dnsclient = $this->getDnsClient();
        $zones = \Metaclassing\Utility::stringToArray($this->zones);
        foreach ($zones as $zone) {
            \App\Utility::log('searching zone '.$zone.' for _acme-challenge. TXT records to clean up');

            if ($this->authprovider == 'cloudflare') {
                $namefield = 'name';
                $idfield = 'id';
            } elseif ($this->authprovider == 'neustarultradns') {
                $namefield = 'ownerName';
                $idfield = 'nameWithoutTld';
            } else {
                throw new \Exception('unknown or unsupported auth provider name and id fields '.$this->authprovider);
            }

            $zonerecords = $dnsclient->getRecords($zone, true);

            \App\Utility::log('zone '.$zone.' contains '.count($zonerecords).' to check for _acme-challenge. TXT clean up');
            foreach ($zonerecords as $record) {
                if ($record['type'] == 'TXT' && preg_match('/^_acme-challenge\./', $record[$namefield], $hits)) {
                    \App\Utility::log('located zone record to clean up '.\Metaclassing\Utility::dumperToString($record));
                    $dnsclient->delZoneRecord($zone, $record[$idfield]);
                }
            }
        }

        return true;
    }

    // Next version of signCertificate, will add support for tracking authorizations and speeding up the signing process
    public function signCertificate($certificate)
    {
        \App\Utility::log('beginning NEW signing process for certificate id '.$certificate->id);

        // Certs must have a valid signing request to begin
        if (! $certificate->request) {
            throw new \Exception('Certificate signing request is empty, did you generate a csr first?');
        }

        // TODO: well this all needs to be rewritten...

        // Get existing or submit new order to begin cert issuance process
        $order = $certificate->makeOrGetOrder($this);
        
        // Get authorizations for order and save them to the database
        $order->makeAuthzForOrder($this);

        // Need to tell authz to go solve themselves now
        // but we don't have the authz object(s) here, so tell order to go tell authz to solve themselves?
        // $order->solvePendingAuthzForCertificate($certificate); ??





        // OLD PROCEDURE

        // Submit order for certificate
        //$this->submitOrderForCertificate($certificate);

        // Ensure authorizations exist for each subject in the certificate
        //$this->makeAuthzForCertificate($certificate);

        // Solve any pending authorization challenges for each subject in the certificate
        //$this->solvePendingAuthzForCertificate($certificate);

        // Validate all authorization challenges are valid for each subject in the certificate
        //$this->validateAllAuthzForCertificate($certificate);

        // Submit our certificate signing request to the authority
        //$this->sendAcmeSigningRequest($certificate);

        // Wait loop for a signed response to our request, or throw an exception to why it failed
        //$this->waitAcmeSignatureSaveCertificate($certificate);

        return true;
    }

    // capculate key authorization from token
    public function calculateKeyAuthorizationFromToken($token)
    {
        // start with the JWK part of our acme header
        //$header = $this->requestHeader()['jwk'];
        $jwk = $this->getJwk();
        // calculate the sha256 hash of the jwk header
        $hash = hash('sha256', json_encode($jwk), true);
        // url-safe base64 encode the hash
        $hash64 = \App\Utility::base64UrlSafeEncode($hash);
        // calculate the token.urlsafeb64jwkhash
        $payload = $token.'.'.$hash64;
        // now hash it all again with sha256
        $keyauth = hash('sha256', $payload, true);
        // url-safe base64 encode the keyauth
        $keyauth64 = \App\Utility::base64UrlSafeEncode($keyauth);
        // and thats what we put in the flat file or dns record...
        return $keyauth64;
    }

    // I wonder if this actually works. maybe i should try using it instead huh
    public function getJwk()
    {
        // Load our key pair and grab the raw key information
        $rsaPrivateKey = new \phpseclib\Crypt\RSA();
        $rsaPrivateKey->loadKey($this->privatekey);
        $rawPublicKey = $rsaPrivateKey->getPublicKey(\phpseclib\Crypt\RSA::PUBLIC_FORMAT_RAW);
        $modulus = \App\Utility::base64UrlSafeEncode($rawPublicKey['n']->toBytes());
        $exponent = \App\Utility::base64UrlSafeEncode($rawPublicKey['e']->toBytes());
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
            $payload64 = \App\Utility::base64UrlSafeEncode(str_replace('\\/', '/', json_encode($payload)));
        }
        $protected64 = \App\Utility::base64UrlSafeEncode(json_encode($protected));
        $plaintext = $protected64.'.'.$payload64;
        $rsaPrivateKey->setHash('sha256');
        $rsaPrivateKey->setMGFHash('sha256');
        $rsaPrivateKey->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PKCS1);
        $signed = $rsaPrivateKey->sign($plaintext);
        $signed64 = \App\Utility::base64UrlSafeEncode($signed);
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

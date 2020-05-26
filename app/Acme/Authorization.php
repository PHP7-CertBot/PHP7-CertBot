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
 * @copyright 2015-2018 @authors
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace App\Acme;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Facades\Log;

class Authorization extends Model implements \OwenIt\Auditing\Contracts\Auditable
{
    use SoftDeletes;
    use \OwenIt\Auditing\Auditable;

    protected $table = 'acme_authorizations';
    protected $fillable = ['account_id', 'identifier', 'challenge', 'status', 'expires'];
    protected $casts = [
        'challenge' => 'array',
    ];

    // Relationships
    public function order()
    {
        return $this->belongsTo(Order::class);
    }

    // Return an associative array of challenge information for the type specified
    public function getChallengeByType($type = 'dns-01')
    {
        $challenges = $this->challenge['challenges'];

        foreach ($challenges as $challenge) {
            if ($challenge['type'] == $type) {
                return $challenge;
            }
        }

        // we should not be here!
        throw new \Exception('Could not identify challenge type '.$type.' in authorization id '.$this->id);
    }

    // build our response to the challenge
    public function buildAcmeResponse($account)
    {
        $challenge = $this->getChallengeByType();
        /*
            $challenge => [
                "url" => "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/49289917/_9LeXQ",
                "type" => "dns-01",
                "token" => "2zw4PN4trPvQbUuFWQ3No98HsTiIvyQqVYS_BwsUZj0",
                "status" => "pending",
            ]
        */

        // Create the dns record we need
        $zone = \Metaclassing\Utility::subdomainToDomain($this->identifier);
        $record = '_acme-challenge.'.$this->identifier;
        $type = 'TXT';
        $keyauth64 = $account->calculateKeyAuthorizationFromToken($challenge['token']);

        // gets the correct DNS client for our auth providers
        $dnsclient = $account->getDnsClient();

        \App\Utility::log('calling dnsClient->addZoneRecord('.$zone.', '.$type.', '.$record.', '.$keyauth64.')');
        try {
            $response = $dnsclient->addZoneRecord($zone, $type, $record, $keyauth64);
            \App\Utility::log($response);
        } catch (\Exception $e) {
            \App\Utility::log('Exception from DNS client: '.$e->getMessage());
            //\App\Utility::log($dnsclient->logs());
        }
    }

    // check our challenge is working properly
    public function checkAcmeResponse($account)
    {
        $challenge = $this->getChallengeByType();
        /*
            $challenge => [
                "url" => "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/49289917/_9LeXQ",
                "type" => "dns-01",
                "token" => "2zw4PN4trPvQbUuFWQ3No98HsTiIvyQqVYS_BwsUZj0",
                "status" => "pending",
            ]
        */

        // Create the dns record we need
        $record = '_acme-challenge.'.$this->identifier;
        $keyauth64 = $account->calculateKeyAuthorizationFromToken($challenge['token']);

        // I am forcing the use of public resolvers as the OS itself may use internal resolvers with overlapping namespaces
        $nameservers = $account->getAuthoritativeNameservers($this->identifier);
        \App\Utility::log('I will attempt to resolve DNS challenges using '.implode(', ', $nameservers));
        $dnsoptions = ['nameservers' => $nameservers];
        $startwait = \Metaclassing\Utility::microtimeTicks();

        // Loop until we get a valid response, or throw exception if we run out of time
        while (true) {
            \App\Utility::log('waiting for dns to propogate. Checking record '.$record.' for value '.$keyauth64);
            try {
                $resolver = new \Net_DNS2_Resolver($dnsoptions);
                $response = $resolver->query($record, 'TXT');
                \App\Utility::log('Resolver returned the following answers: '.\Metaclassing\Utility::dumperToString($response->answer));
                // The correct txt record must be the FIRST & only TXT record for our _acme-challenge name
                if ($response->answer[0]->text[0] == $keyauth64) {
                    \App\Utility::log('acme dns response succeeded, breaking out of wait loop');
                    //\App\Utility::log('Waiting 30 seconds because multi-location acme dns verification can take extra time');
                    //sleep(30);
                    break;
                } else {
                    throw new \Exception('Unable to validate Acme challenge, expected payload '.$keyauth64.' but recieved '.$response->answer[0]->text[0]);
                }
            } catch (\Exception $e) {
                \App\Utility::log('DNS resolution exception: '.$e->getMessage());
            }
            // Handle if we run out of time waiting for DNS to update
            if (\Metaclassing\Utility::microtimeTicks() - $startwait > 180) {
                throw new \Exception('Unable to validate Acme challenge, maximum DNS wait time exceeded');
            }
            // Wait a couple seconds and try again
            sleep(10);
        }
        \App\Utility::log('validated '.$keyauth64.' at '.$record);
    }

    // send our challenge authorization back to the acme ca
    public function respondAcmeChallenge($account)
    {
        // send response to challenge
        $challenge = $this->getChallengeByType();
        \App\Utility::log('sent challenge response to url '.$challenge['url'].' waiting for reply');
        $result = $account->signedRequest($challenge['url'], new \stdClass());
        \App\Utility::log('got response from challenge url: '.json_encode($result));

        // IF we get nonce-blocked here because our previous nonce is likely expired or something try one last time before giving up
        if ($account->client->getLastCode() != 200) {
            \App\Utility::log('last code from challenge post was '.$account->client->getLastCode().' so trying one last time...');
            $result = $account->signedRequest($challenge['url'], new \stdClass());
            \App\Utility::log('final attempt response from challenge url: '.json_encode($result));
        }

        $tries = 0;
        // loop until we are valid or encounter an exception
        while ($result['status'] != 'valid') {
            if ($result['status'] != 'pending' && $result['status'] != 'valid') {
                \App\Utility::log('verification errors with response json '.json_encode($result));
                throw new \RuntimeException('DNS verification failed with error: '.json_encode($result));
            }

            if ($tries++ > 5) {
                \App\Utility::log('verification not valid after 5 tries, giving up for now '.json_encode($result));
                throw new \RuntimeException('verification pending after 5 tries, giving up for now '.json_encode($result));
            }

            if ($result['status'] == 'pending') {
                \App\Utility::log('Verification pending, sleeping 10s');
                sleep(10);
            }
            $result = $account->signedRequest($challenge['url'], false);
        }

        \App\Utility::log('challenge verification 2 successful');
        // Save the outcome of our challenge response
        $this->status = $result['status'];
        $this->save();
    }

    public function cleanupAcmeChallengeDns01($account)
    {
        $dnsclient = $account->getDnsClient();
        $zone = \Metaclassing\Utility::subdomainToDomain($this->identifier);
        \App\Utility::log('searching zone '.$zone.' for _acme-challenge. TXT records to clean up');

        if ($account->authprovider == 'cloudflare') {
            $namefield = 'name';
            $idfield = 'id';
        } elseif ($account->authprovider == 'neustarultradns') {
            $namefield = 'ownerName';
            $idfield = 'nameWithoutTld';
        } else {
            throw new \Exception('unknown or unsupported auth provider name and id fields '.$account->authprovider);
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
}

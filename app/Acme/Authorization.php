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

        foreach($challenges as $challenge) {
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
        $keyauth64 = $account->calculateKeyAuthorizationFromToken($token);

        // gets the correct DNS client for our auth providers
        $dnsclient = $account->getDnsClient();

        $account->log('calling dnsClient->addZoneRecord('.$zone.', '.$type.', '.$record.', '.$keyauth64.')');
        try {
            $response = $dnsclient->addZoneRecord($zone, $type, $record, $keyauth64);
            $account->log($response);
        } catch (\Exception $e) {
            $account->log('Exception from DNS client: '.$e->getMessage());
            //$account->log($dnsclient->logs());
        }

        return;
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
        $zone = \Metaclassing\Utility::subdomainToDomain($this->identifier);
        $record = '_acme-challenge.'.$this->identifier;
        $type = 'TXT';
        $keyauth64 = $account->calculateKeyAuthorizationFromToken($token);

        // I am forcing the use of public resolvers as the OS itself may use internal resolvers with overlapping namespaces
        $nameservers = $account->getAuthoritativeNameservers($this->identifier);
        $this->log('I will attempt to resolve DNS challenges using '.implode(', ', $nameservers));
        $dnsoptions = ['nameservers' => $nameservers];
        $startwait = \Metaclassing\Utility::microtimeTicks();

        // Loop until we get a valid response, or throw exception if we run out of time
        while (true) {
            $account->log('waiting for dns to propogate. Checking record '.$record.' for value '.$keyauth64);
            try {
                $resolver = new \Net_DNS2_Resolver($dnsoptions);
                $response = $resolver->query($record, 'TXT');
                $account->log('Resolver returned the following answers: '.\Metaclassing\Utility::dumperToString($response->answer));
                // The correct txt record must be the FIRST & only TXT record for our _acme-challenge name
                if ($response->answer[0]->text[0] == $keyauth64) {
                    $account->log('Waiting 30 seconds because multi-location acme dns verification can take extra time');
                    sleep(30);
                    break;
                } else {
                    throw new \Exception('Unable to validate Acme challenge, expected payload '.$keyauth64.' but recieved '.$response->answer[0]->text[0]);
                }
            } catch (\Exception $e) {
                $account->log('DNS resolution exception: '.$e->getMessage());
            }
            // Handle if we run out of time waiting for DNS to update
            if (\Metaclassing\Utility::microtimeTicks() - $startwait > 180) {
                throw new \Exception('Unable to validate Acme challenge, maximum DNS wait time exceeded');
            }
            // Wait a couple seconds and try again
            sleep(10);
        }
        $account->log('validated '.$keyauth64.' at '.$record);

        return $payload;
    }

    // TODO: this needs to be rewritten...

    // send our challenge authorization back to the acme ca
    public function respondAcmeChallenge($authz)
    {
        // send response to challenge
        $challenge = $this->getChallengeByType();
        $response = $this->signedRequest($challenge['url'], false);
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
                $this->log('Verification pending, sleeping 10s');
                sleep(10);
            }
            $result = $this->client->get($challenge['location']);
            //$result = $this->signedRequest($challenge['location'], []);

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

}

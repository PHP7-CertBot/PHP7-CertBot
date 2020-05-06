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

class Order extends Model implements \OwenIt\Auditing\Contracts\Auditable
{
    use SoftDeletes;
    use \OwenIt\Auditing\Auditable;

    protected $table = 'acme_orders';
    protected $fillable = ['certificate_id', 'status', 'expires', 'notBefore', 'notAfter', 'error', 'finalizeUrl', 'certificateUrl'];
    protected $casts = [
        'identifiers'       => 'array',
        'authorizationUrls' => 'array',
        'error'             => 'array',
    ];

    // Relationships
    public function certificate()
    {
        return $this->belongsTo(Certificate::class);
    }

    public function authorizations()
    {
        return $this->hasMany(Authorization::class);
    }

    public function pendingAuthorizations()
    {
        return $this->hasMany(Authorization::class)
                    ->where('status', 'pending');
//                  ->whereDate('expires', '>', \Carbon\Carbon::today()->toDateString())
    }

    public function makeAuthzForOrder($account)
    {
        $orderAuthorizationUrls = $this->authorizationUrls;

        // Loop through all the authz urls and get the authz information to create our acme_authorization objects...
        foreach($orderAuthorizationUrls as $authorizationUrl) {
            // get a new challenge authorization from the CA
            $response = $account->signedRequest($authorizationUrl, false);

            // TODO: Handle failures if signed request fails here for some reason...
            $subject = $response['identifier']['value'];
            // or throw an exception

            $key = [
                    'order_id' => $this->id,
                    'identifier' => $subject,
                   ];

            // Get the existing expired or create a new authz with the order id and subject
            $authz = Authorization::firstOrNew($key);

            // save it to our new or existing challenge
            $authz->order_id = $this->id;
            $authz->challenge = $response;
            $authz->status = $response['status'];
            $authz->expires = $response['expires'];
            $authz->save();
        }
    }

    public function sendAcmeSigningRequest($account)
    {
        if ($this->status != 'ready') {
            throw new \Exception('order id '.$this->id.' status is not ready, it is '.$this->status);
        }

        \App\Utility::log('sending certificate request to be signed');
        // read our CSR but strip off first/last ----- lines -----

        $csr = $this->certificate->getCsrContent();
        // request certificates creation
        $payload = [
            'csr' => $csr
        ];
        $result = $account->signedRequest($this->finalizeUrl, $payload );
        if ($account->client->getLastCode() !== 200) {
            throw new \RuntimeException('Invalid response code: '.$account->client->getLastCode().', '.json_encode($result));
        }
        \App\Utility::log('certificate signing request sent successfully');

        // update the order with data returned from the finalize URL
        $this->status = $result['status'];
        $this->expires = $result['expires'];
        $this->identifiers = $result['identifiers'];
        $this->authorizationUrls = $result['authorizations'];
        $this->finalizeUrl = $result['finalize'];
        if(isset($result['certificate'])) {
            $this->certificateUrl = $result['certificate'];
        } else {
            \App\Utility::log('updated cert status is now '.$this->status.' but no certificate url');
        }

        // this is the waiting loop to get an updated status until its valid and the cert is ready...
        return;
    }

    //TODO: this needs to be completely rewritten to wait for the finalize call to spit back a certificate url and then call it to get the cert.
    // The finalize call returns the order object with a URL value assigned to 'certificateUrl'.
    // POST-as-GET to certificateUrl to download the cert chain.
    public function waitAcmeSignature($account)
    {
        $certificates = [];

        // get the order url from the Location header
        // this should be the actual order URL like https://acme-staging-v02.api.letsencrypt.org/acme/order/236957/8790400
        $order_url = $account->client->getLastLocation();

        // Need to account for orders being in a "processing" state here. Per RFC8555:
        // Send a POST-as-GET request after the time given in the Retry-After header field of the response, if any.

        $tries = 0;
        while ($this->status != 'valid') {
            // get recommended time to wait from 'Retry-After' header in the response
            // could be an integer or HTTP date, so just log it for now
            $wait_time = $account->client->getRetryAfter();
            $wait_time++;
            $wait_time++;
            \App\Utility::log('order processing, recommended wait time is '.$wait_time);
            // Not sure if sleep() is the best thing to use here.
            sleep($wait_time);

            // POST-as-GET for updated order
            $result = $account->signedRequest($order_url, false);

            if ($account->client->getLastCode() !== 200) {
                throw new \RuntimeException('Invalid response code: '.$account->client->getLastCode().', '.json_encode($result));
            }

            if ($tries++ > 5) {
                throw new \RuntimeException('waited 5 tries to save signed certificate, aborting with last response '.json_encode($result));
            }

            // update the order with data returned from the order url
            $this->status = $result['status'];
            $this->expires = $result['expires'];
            $this->identifiers = $result['identifiers'];
            $this->authorizationUrls = $result['authorizations'];
            $this->finalizeUrl = $result['finalize'];
            if(isset($result['certificate'])) {
                $this->certificateUrl = $result['certificate'];
            } else {
                \App\Utility::log('updated cert status is now '.$this->status.' but no certificate url');
            }
        }

        return;
    }

    // TODO: move the rest of this into a save certificate function that assumes wait sign is all complete and good
    public function saveAcmeCertificates($account)
    {
        if ($this->status != 'valid') {
            throw new \Exception('order id '.$this->id.' status is not valid, it is '.$this->status);
        }

        \App\Utility::log('sending POST for certificate chain to '.$this->certificateUrl);
        $result = $account->signedRequest($this->certificateUrl, false);

        // if we get anything other than 200 OK then pop smoke
        if ($account->client->getLastCode() != 200) {
            throw new \RuntimeException('Invalid response code: '.$account->client->getLastCode().', '.json_encode($result));
        }

        \App\Utility::log('got certificate! YAY!');
        preg_match_all('/-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/s', $result, $certificates);
        // preg match all gives us double nested arrays, we need to un-nest it.
        $certificates = reset($certificates);

        // if certificates is empty then pop smoke
        if (empty($certificates)) {
            throw new \RuntimeException('No certificates in response!');
        }

        // save certificate to database
        $certificate = $this->certificate;
        $certificate->certificate = array_shift($certificates);
        $certificate->chain = implode("\n", $certificates);
        $certificate->updateExpirationDate();
        $certificate->status = 'signed';
        $certificate->save();

        return;
    }

    public function solvePendingAuthz($account)
    {
        // Get all pending authz that need to be solved before requesting a signed certificate
        $authorizations = $this->pendingAuthorizations;

        // Put the authorization solving in a try catch block for error handling
        try {
            // First try to build responses to solve each challenge (create dns records)
            foreach ($authorizations as $authz) {
                \App\Utility::log('building authz response id '.$authz->id);
                $authz->buildAcmeResponse($account);
            }
            // Then check the acme response to each challenge
            foreach ($authorizations as $authz) {
                \App\Utility::log('checking authz response id '.$authz->id);
                // Save the payload temporarily as we use it in the next step
                $authz->checkAcmeResponse($account);
            }
            // Then respond to each challenge with the ACME CA
            foreach ($authorizations as $authz) {
                \App\Utility::log('responding to authz id '.$authz->id);
                $authz->respondAcmeChallenge($account);
            }

        // if we hit any snags, just log it so it can get resolved
        } catch (\Exception $e) {
            // Always run the cleanup afterwards
            \App\Utility::log('caught exception while solving authz '.$e->getMessage());
            \App\Utility::log($e->getTraceAsString());
        } finally {
            foreach ($authorizations as $authz) {
                $authz->cleanupAcmeChallengeDns01($account);
            }
        }

        return;
    }

}


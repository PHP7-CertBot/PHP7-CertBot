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

class Order extends Model implements \OwenIt\Auditing\Contracts\Auditable
{
    use SoftDeletes;
    use \OwenIt\Auditing\Auditable;

    protected $table = 'acme_orders';
    protected $fillable = ['account_id', 'certificate_id', 'status', 'expires', 'notBefore', 'notAfter', 'error', 'finalize', 'certificate'];
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
        return $this->hasMany(Authorizations::class);
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

            // Get the existing expired or create a new authz with the account id and subject
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
        $this->log('sending certificate request to be signed');
        // read our CSR but strip off first/last ----- lines -----

        $csr = $this->certificate->getCsrContent();
        // request certificates creation
        $result = $this->signedRequest(
            $this->finalize,
            [
                'csr'      => $csr,
            ]
        );
        if ($this->client->getLastCode() !== 201) {
            throw new \RuntimeException('Invalid response code: '.$this->client->getLastCode().', '.json_encode($result));
        }
        $this->log('certificate signing request sent successfully');

        return true;
    }

    //TODO: this needs to be completely rewritten to wait for the finalize call to spit back a certificate url and then call it to get the cert.
    public function waitAcmeSignatureSaveCertificate($account)
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

    // TODO: this needs to turn into solvePendingAuthzForOrder($account)
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

    // TODO: this turns into validateAllAuthzForOrder($account)
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

}

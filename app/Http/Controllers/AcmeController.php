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

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class AcmeController extends CertbotController
{
    /*
    |--------------------------------------------------------------------------
    | ACME controller
    |--------------------------------------------------------------------------
    |
        This controller handles creating and using ACME Account information
    |
    */

    /**
     * Create a new account controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        // Set the correct account and certificate types for common controller functions
        $this->accountType = 'App\Acme\Account';
        $this->certificateType = 'App\Acme\Certificate';

        // Always call our parents constructor
        parent::__construct();
    }

    public function createAccount(Request $request)
    {
        $user = auth()->user();
        if (! $user->can('create', $this->accountType)) {
            abort(401, 'You are not authorized to create new accounts');
        }
        $account = $this->accountType::create($request->all());
        $account->status = 'new';
        $account->generateKeys();

        $response = [
            'success' => true,
            'message' => '',
            'request' => $request->all(),
            'account' => $account,
        ];

        return response()->json($response);
    }

    public function registerAccount($account_id)
    {
        $user = auth()->user();
        $account = $this->accountType::findOrFail($account_id);
        if (! $user->can('create', $account)) {
            abort(401, 'You are not authorized to register account id '.$account_id);
        }
        $response = [];
        try {
            $response['account'] = $account;
            $response['acme'] = $account->postNewReg();
            $response['success'] = true;
            $response['message'] = 'registered account to acme ca for id '.$account_id;
        } catch (\Exception $e) {
            $response['success'] = false;
            $response['message'] = 'encountered exception: '.$e->getMessage();
        }

        return response()->json($response);
    }

    public function updateAccountRegistration($account_id)
    {
        $user = auth()->user();
        $account = $this->accountType::findOrFail($account_id);
        if (! $user->can('update', $account)) {
            abort(401, 'You are not authorized to register account id '.$account_id);
        }
        $response = [];
        try {
            $response['account'] = $account;
            $response['acme'] = $account->postUpdateReg();
            $response['success'] = true;
            $response['message'] = 'updated registered account to acme ca for id '.$account->id;
        } catch (\Exception $e) {
            $response['success'] = false;
            $response['message'] = 'encountered exception: '.$e->getMessage();
        }

        return response()->json($response);
    }

    public function createCertificate(Request $request, $account_id)
    {
        $user = auth()->user();
        $account = $this->accountType::findOrFail($account_id);
        if (! $this->viewAuthorizedAccount($user, $account)) {
            abort(401, 'You are not authorized to create certificates for account id '.$account_id);
        }
        // make sure each top level domain in this cert are in the permitted zone list for this account
        $allowedzones = \Metaclassing\Utility::stringToArray($account->zones);
        $input = $request->all();
        if (! $input['subjects']) {
            abort(400, 'Did not get any subjects in request');
        }
        // In case subjects are submitted as a whitespace delimited string rather than array, convert them to an array
        if (! is_array($input['subjects'])) {
            $input['subjects'] = \Metaclassing\Utility::stringToArray($input['subjects']);
        }
        // remove empty elements from subjects array if there are any
        $input['subjects'] = array_filter($input['subjects'], 'strlen');
        Log::info('got create cerrt request with input '.json_encode($input));

        foreach ($input['subjects'] as $subject) {
            $topleveldomain = \Metaclassing\Utility::subdomainToDomain($subject);
            Log::info('evaluating subject '.$subject.' against tld '.$topleveldomain);
            if (! in_array($topleveldomain, $allowedzones)) {
                throw new \Exception('domain '.$subject.' tld '.$topleveldomain.' is not in this accounts list of permitted zones: '.$account->zones);
            }
            if ($subject != strtolower($subject)) {
                throw new \Exception('Subject '.$subject.' should only contain lower case dns-valid characters');
            }
            Log::info('strpos , is '.strpos($subject, ' '));
            if (strpos($subject, ' ') !== false) {
                throw new \Exception('Subject '.$subject.' contains a space which is not a dns-valid character');
            }
            if (strpos($subject, ',') !== false) {
                throw new \Exception('Subject '.$subject.' contains a comma which is not a dns-valid character');
            }
            if ($subject[0] == '*') {
                throw new \Exception('Subject '.$subject.' is a wildcard, dont do that.');
            }
        }
        // manual check for duplicates, moved out of the database to the code
        $dupes = $account->certificates->where('name', $input['name']);
        if (count($dupes)) {
            throw new \Exception('Account id '.$account->id.' already has a cert named '.$input['name']);
        }

        $certificate = $account->certificates()->create($input);
        Log::info('user id '.$user->id.' created new '.$this->accountType.' id '.$account_id.' certificate id '.$certificate->id);

        // Send back everything
        $response = [
            'success'     => true,
            'message'     => '',
            'request'     => $request->all(),
            'certificate' => $certificate,
        ];

        return response()->json($response);
    }
}

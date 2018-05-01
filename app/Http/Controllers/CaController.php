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
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Log;

class CaController extends CertbotController
{
    /*
    |--------------------------------------------------------------------------
    | Ca controller
    |--------------------------------------------------------------------------
    |
        This controller handles creating and using Ca Account information
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
        $this->accountType = 'App\Ca\Account';
        $this->certificateType = 'App\Ca\Certificate';

        // Always call our parents constructor
        parent::__construct();
    }

    public function createAccount(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        if (! $user->can('create', $this->accountType)) {
            abort(401, 'You are not authorized to create new accounts');
        }
        $account = $this->accountType::create($request->all());
        $account->status = 'new';

        $response = [
                    'success' => true,
                    'message' => '',
                    'request' => $request->all(),

                    'account' => $account,
                    ];

        return response()->json($response);
    }

    public function createCertificate(Request $request, $account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = $this->accountType::findOrFail($account_id);
        if (! $this->viewAuthorizedAccount($user, $account)) {
            abort(401, 'You are not authorized to create certificates for account id '.$account_id);
        }

        // TODO: make sure each top level domain in this cert are in the permitted zone list for this account

        $certificate = $account->certificates()->create($request->all());
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

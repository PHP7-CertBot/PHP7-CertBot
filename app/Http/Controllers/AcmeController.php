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

use App\Acme\Account;
use App\Acme\Certificate;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;

class AcmeController extends Controller
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
        // Only authenticated users can make these calls
        $this->middleware('jwt.auth', ['except' => ['certificateRefreshPEM', 'certificateRefreshP12']]);
    }

    public function createAccount(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        if (! $user->can('create', Account::class)) {
            abort(401, 'You are not authorized to create new accounts');
        }
        $account = Account::create($request->all());
        $account->status = 'new';
        $account->generateKeys();
        // This might fail and I need to figure out wtf to do
        $acme = $account->postNewReg();
        $response = [
                    'success' => true,
                    'message' => '',
                    'request' => $request->all(),
                    'acme'    => $acme,
                    'account' => $account,
                    ];

        return response()->json($response);
    }

    public function deleteAccount($account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        if (! $user->can('delete', Account::class)) {
            abort(401, 'You are not authorized to delete account id '.$account_id);
        }
        $account = Account::findOrFail($account_id);
        $account->delete();
        $response = [
                    'success'    => true,
                    'message'    => 'ACME account id '.$account_id.' successfully deleted',
                    'deleted_at' => $account->deleted_at, ];

        return response()->json($response);
    }

    public function viewAuthorizedAccount($user, $account)
    {
        if ($user->can('read', $account)) {
            return $account;
        }

        return false;
    }

    // This handles both account level privileges and individual cert level permissions
    public function viewAuthorizedCertificate($user, $account, $certificate)
    {
        if ($user->can('read', $account)
        || $user->can('read', $certificate)) {
            return $certificate;
        }

        return false;
    }

    public function listAccounts()
    {
        $user = JWTAuth::parseToken()->authenticate();
        $accounts = Account::all();
        $show = [];
        foreach ($accounts as $account) {
            if ($this->viewAuthorizedAccount($user, $account)) {
                $show[] = $account;
            }
        }
        $response = [
                    'success'  => true,
                    'message'  => '',
                    'accounts' => $show,
                    ];

        return response()->json($response);
    }

    public function getAccount($account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        if (! $this->viewAuthorizedAccount($user, $account)) {
            abort(401, 'You are not authorized to access account id '.$account_id);
        }
        $response = [
                    'success' => true,
                    'message' => '',
                    'account' => $account,
                    ];

        return response()->json($response);
    }

    public function registerAccount($account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
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
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
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

    public function updateAccount(Request $request, $account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        if (! $user->can('update', $account)) {
            abort(401, 'You are not authorized to update account id '.$account_id);
        }
        $account->fill($request->all());
        $account->save();
        $response = [
                    'success' => true,
                    'message' => '',
                    'request' => $request->all(),
                    'account' => $account,
                    ];

        return response()->json($response);
    }

    public function listCertificates($account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificates = Certificate::where('account_id', $account_id)->get();
        $show = [];
        foreach ($certificates as $certificate) {
            if ($this->viewAuthorizedCertificate($user, $account, $certificate)) {
                $show[] = $certificate;
            }
        }
        $response = [
                    'success'      => true,
                    'message'      => '',
                    'certificates' => $show,
                    ];

        return response()->json($response);
    }

    public function getCertificate($account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to access account id '.$account_id.' certificate id '.$certificate_id);
        }
        Log::info('user id '.$user->id.' viewed acme account id '.$account_id.' certificate id '.$certificate_id);
        $response = [
                    'success'     => true,
                    'message'     => '',
                    'certificate' => $certificate,
                    ];

        return response()->json($response);
    }

    public function createCertificate(Request $request, $account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        if (! $this->viewAuthorizedAccount($user, $account)) {
            abort(401, 'You are not authorized to create certificates for account id '.$account_id);
        }
        // make sure each top level domain in this cert are in the permitted zone list for this account
        $allowedzones = \Metaclassing\Utility::stringToArray($account->zones);
        $subjects = $request->input('subjects');
        // In case subjects are submitted as a whitespace delimited string rather than array, convert them to an array
        if (! is_array($subjects)) {
            $subjects = \Metaclassing\Utility::stringToArray($subjects);
        }
        foreach ($subjects as $subject) {
            $topleveldomain = \Metaclassing\Utility::subdomainToDomain($subject);
            if (! in_array($topleveldomain, $allowedzones)) {
                throw new \Exception('domain '.$subject.' tld '.$topleveldomain.' is not in this accounts list of permitted zones: '.$account->zones);
            }
            if ($subject != strtolower($subject)) {
                throw new \Exception('Subject '.$subject.' should only contain lower case dns-valid characters');
            }
        }
        $certificate = $account->certificates()->create($request->all());
        Log::info('user id '.$user->id.' created new acme account id '.$account_id.' certificate id '.$certificate->id);
        //$certificate->generateKeys();

        // Send back everything
        $response = [
                    'success'     => true,
                    'message'     => '',
                    'request'     => $request->all(),
                    'certificate' => $certificate,
                    ];

        return response()->json($response);
    }

    public function updateCertificate(Request $request, $account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::findOrFail($certificate_id);
        if (! $user->can('create', $account)
        && ! $user->can('update', $account)
        && ! $user->can('update', $certificate)) {
            abort(401, 'You are not authorized to update certificate for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->fill($request->all());
        $certificate->save();
        Log::info('user id '.$user->id.' updated acme account id '.$account_id.' certificate id '.$certificate->id);
        $response = [
                    'success'     => true,
                    'message'     => '',
                    'request'     => $request->all(),
                    'certificate' => $certificate,
                    ];

        return response()->json($response);
    }

    public function deleteCertificate($account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::findOrFail($certificate_id);
        if (! $user->can('delete', $account)
        && ! $user->can('delete', $certificate)) {
            abort(401, 'You are not authorized to delete certificate for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->delete();
        Log::info('user id '.$user->id.' deleted acme account id '.$account_id.' certificate id '.$certificate_id);
        $response = [
                    'success'    => true,
                    'message'    => 'Acme certificate id '.$certificate_id.' successfully deleted',
                    'deleted_at' => $certificate->deleted_at, ];

        return response()->json($response);
    }

    public function certificateGenerateKeys($account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to generate keys for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->generateKeys();
        Log::info('user id '.$user->id.' generated new keys for acme account id '.$account_id.' certificate id '.$certificate_id);
        // Send back everything
        $response = [
                    'success'     => true,
                    'message'     => 'generated new keys for cert id '.$certificate_id,
                    'certificate' => $certificate,
                    ];

        return response()->json($response);
    }

    public function certificateGenerateRequest($account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to generate certificate signing requests for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->generateRequest();
        Log::info('user id '.$user->id.' generated new csr for acme account id '.$account_id.' certificate id '.$certificate_id);
        // Send back everything
        $response = [
                    'success'     => true,
                    'message'     => 'generated new signing request for cert id '.$certificate_id,
                    'certificate' => $certificate,
                    ];

        return response()->json($response);
    }

    public function certificateSign($account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $user->can('sign', $account)
        && ! $user->can('sign', $certificate)) {
            abort(401, 'You are not authorized to sign requests for account id '.$account_id.' certificate id '.$certificate_id);
        }
        Log::info('user id '.$user->id.' started signing request for acme account id '.$account_id.' certificate id '.$certificate_id);
        $response = [];
        try {
            $account->signCertificate($certificate);
            $response['success'] = true;
            $response['message'] = 'signed certificate id '.$certificate->id;
            $response['log'] = $account->log();
        } catch (\Exception $e) {
            $response['success'] = false;
            $response['message'] = 'encountered exception: '.$e->getMessage();
            $response['log'] = $account->log();
        }
        Log::info('user id '.$user->id.' finished signing request for acme account id '.$account_id.' certificate id '.$certificate_id.' with status '.$response['success']);

        return response()->json($response);
    }

    public function certificateRenew($account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $user->can('sign', $account)
        && ! $user->can('sign', $certificate)) {
            abort(401, 'You are not authorized to sign requests for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $response = [];
        try {
            $account->renewCertificate($certificate);
            $response['success'] = true;
            $response['message'] = 'renewed certificate id '.$certificate->id;
            $response['log'] = $account->log();
        } catch (\Exception $e) {
            $response['success'] = false;
            $response['message'] = 'encountered renew exception: '.$e->getMessage();
            $response['log'] = $account->log();
        }

        return response()->json($response);
    }

    public function certificateDownloadPKCS12(Request $request, $account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to download PKCS12 for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $password = $request->input('password');
        Log::info('pkcs12 will use password '.$password);
        Log::info('user id '.$user->id.' downloaded pkcs12 acme account id '.$account_id.' certificate id '.$certificate_id);
        if (! $certificate->privatekey) {
            abort(400, 'Certificate does not have a key pair assigned');
        }
        if (! $certificate->privatekey || ! $certificate->certificate || $certificate->status != 'signed') {
            abort(400, 'Certificate is not signed');
        }
        $pkcs12 = $certificate->generateDownloadPKCS12($password);
        $headers = [
                    'Content-Type'            => 'application/x-pkcs12',
                    'Content-Length'          => strlen($pkcs12),
                    'Content-Disposition'     => 'filename="certbot.p12"',
                    ];

        return response()->make($pkcs12, 200, $headers);
    }

    public function certificateDownloadPEM(Request $request, $account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to download PEM for account id '.$account_id.' certificate id '.$certificate_id);
        }
        if (! $certificate->privatekey) {
            abort(400, 'Certificate does not have a key pair assigned');
        }
        if (! $certificate->privatekey || ! $certificate->certificate || $certificate->status != 'signed') {
            abort(400, 'Certificate is not signed');
        }
        $pem = $certificate->privatekey.PHP_EOL
             .$certificate->certificate.PHP_EOL
             .$certificate->chain.PHP_EOL;
        Log::info('user id '.$user->id.' downloaded pem acme account id '.$account_id.' certificate id '.$certificate_id);
        $headers = [
                    'Content-Type'            => 'application/x-pem-file',
                    'Content-Length'          => strlen($pem),
                    'Content-Disposition'     => 'filename="certbot.pem"',
                    ];

        return response()->make($pem, 200, $headers);
    }

    public function certificateRefreshPEM(Request $request, $account_id, $certificate_id)
    {
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        // Alternate authentication mechanism for existing servers to use their key hash to get an updated certificate ONLY
        $keyHash = $request->input('keyhash');
        if ($keyHash != $certificate->getPrivateKeyHash()) {
            abort(401, 'Hash authorization failure for account id '.$account_id.' certificate id '.$certificate_id);
        }
        Log::info('priv key has auth '.$keyHash.' viewed acme account id '.$account_id.' certificate id '.$certificate_id);
        $pem = $certificate->privatekey.PHP_EOL
             .$certificate->certificate.PHP_EOL
             .$certificate->chain.PHP_EOL;
        $headers = [
                    'Content-Type'            => 'application/x-pem-file',
                    'Content-Length'          => strlen($pem),
                    'Content-Disposition'     => 'filename="certbot.pem"',
                    ];

        return response()->make($pem, 200, $headers);
    }

    public function certificateRefreshP12(Request $request, $account_id, $certificate_id)
    {
        $account = Account::findOrFail($account_id);
        $certificate = Certificate::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        // Alternate authentication mechanism for existing servers to use their key hash to get an updated certificate ONLY
        $keyHash = $request->input('keyhash');
        if ($keyHash != $certificate->getPrivateKeyHash()) {
            abort(401, 'Hash authorization failure for account id '.$account_id.' certificate id '.$certificate_id);
        }
        if (! $certificate->privatekey || ! $certificate->certificate || $certificate->status != 'signed') {
            abort(400, 'Certificate is not signed');
        }
        Log::info('priv key has auth '.$keyHash.' viewed acme account id '.$account_id.' certificate id '.$certificate_id);
        $password = $request->input('password');
        Log::info('pkcs12 will use password '.$password);
        $pkcs12 = $certificate->generateDownloadPKCS12($password);
        $headers = [
                    'Content-Type'            => 'application/x-pkcs12',
                    'Content-Length'          => strlen($pkcs12),
                    'Content-Disposition'     => 'filename="certbot.p12"',
                    ];

        return response()->make($pkcs12, 200, $headers);
    }
}

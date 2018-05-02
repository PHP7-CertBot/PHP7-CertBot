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
use App\Http\Controllers\Controller;

abstract class CertbotController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Certbot controller
    |--------------------------------------------------------------------------
    |
        This is a base controller acme and ca use for common functionality
    |
    */

    protected $accountType = '';
    protected $certificateType = '';

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

    abstract public function createAccount(Request $request);

    public function deleteAccount($account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        if (! $user->can('delete', $this->accountType)) {
            abort(401, 'You are not authorized to delete account id '.$account_id);
        }
        $account = $this->accountType::findOrFail($account_id);
        $account->delete();
        $response = [
                    'success'    => true,
                    'message'    => $this->accountType.' account id '.$account_id.' successfully deleted',
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
        $accounts = $this->accountType::all();
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
        $account = $this->accountType::findOrFail($account_id);
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

    public function updateAccount(Request $request, $account_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = $this->accountType::findOrFail($account_id);
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
        $account = $this->accountType::findOrFail($account_id);
        $certificates = $this->certificateType::where('account_id', $account_id)->get();
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
        $account = $this->accountType::findOrFail($account_id);
        $certificate = $this->certificateType::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to access account id '.$account_id.' certificate id '.$certificate_id);
        }
        Log::info('user id '.$user->id.' viewed '.$this->accountType.' account id '.$account_id.' certificate id '.$certificate_id);
        $response = [
                    'success'     => true,
                    'message'     => '',
                    'certificate' => $certificate,
                    ];

        return response()->json($response);
    }

    abstract public function createCertificate(Request $request, $account_id);

    public function updateCertificate(Request $request, $account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = $this->accountType::findOrFail($account_id);
        $certificate = $this->certificateType::findOrFail($certificate_id);
        if (! $user->can('create', $account)
        && ! $user->can('update', $account)
        && ! $user->can('update', $certificate)) {
            abort(401, 'You are not authorized to update certificate for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->fill($request->all());
        $certificate->save();
        Log::info('user id '.$user->id.' updated '.$this->accountType.' account id '.$account_id.' certificate id '.$certificate->id);
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
        $account = $this->accountType::findOrFail($account_id);
        $certificate = $this->certificateType::findOrFail($certificate_id);
        if (! $user->can('delete', $account)
        && ! $user->can('delete', $certificate)) {
            abort(401, 'You are not authorized to delete certificate for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->delete();
        Log::info('user id '.$user->id.' deleted '.$this->accountType.' account id '.$account_id.' certificate id '.$certificate_id);
        $response = [
                    'success'    => true,
                    'message'    => $this->certificateType.' id '.$certificate_id.' successfully deleted',
                    'deleted_at' => $certificate->deleted_at, ];

        return response()->json($response);
    }

    public function certificateGenerateKeys($account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = $this->accountType::findOrFail($account_id);
        $certificate = $this->certificateType::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to generate keys for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->generateKeys();
        Log::info('user id '.$user->id.' generated new keys for '.$this->accountType.' account id '.$account_id.' certificate id '.$certificate_id);
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
        $account = $this->accountType::findOrFail($account_id);
        $certificate = $this->certificateType::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to generate certificate signing requests for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->generateRequest();
        Log::info('user id '.$user->id.' generated new csr for '.$this->accountType.' id '.$account_id.' certificate id '.$certificate_id);
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
        $account = $this->accountType::findOrFail($account_id);
        $certificate = $this->certificateType::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $user->can('sign', $account)
        && ! $user->can('sign', $certificate)) {
            abort(401, 'You are not authorized to sign requests for account id '.$account_id.' certificate id '.$certificate_id);
        }
        Log::info('user id '.$user->id.' started signing request for '.$this->accountType.' id '.$account_id.' certificate id '.$certificate_id);
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
        Log::info('user id '.$user->id.' finished signing request for '.$this->accountType.' id '.$account_id.' certificate id '.$certificate_id.' with status '.$response['success']);

        return response()->json($response);
    }

    public function certificateDownloadPKCS12(Request $request, $account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = $this->accountType::findOrFail($account_id);
        $certificate = $this->certificateType::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to download PKCS12 for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $password = $request->input('password');
        Log::info('pkcs12 will use password '.$password);
        Log::info('user id '.$user->id.' downloaded pkcs12 '.$this->accountType.' id '.$account_id.' certificate id '.$certificate_id);
        if (! $certificate->privatekey) {
            abort(400, 'Certificate does not have a key pair assigned');
        }
        if (! $certificate->privatekey || ! $certificate->certificate || $certificate->status != 'signed') {
            abort(400, 'Certificate is not signed');
        }
        $pkcs12 = $certificate->generateDownloadPKCS12($password);
        $refreshUri = $request->url().'/refresh?keyhash='.$certificate->getPrivateKeyHash();
        $headers = [
                    'Content-Type'            => 'application/x-pkcs12',
                    'Content-Length'          => strlen($pkcs12),
                    'Content-Disposition'     => 'filename="certbot.p12"',
                    'Link'                    => '<'.$refreshUri.'>; rel="alternate";',
                    ];

        return response()->make($pkcs12, 200, $headers);
    }

    public function certificateDownloadPEM(Request $request, $account_id, $certificate_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $account = $this->accountType::findOrFail($account_id);
        $certificate = $this->certificateType::where('id', $certificate_id)
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
        Log::info('user id '.$user->id.' downloaded pem '.$this->accountType.' account id '.$account_id.' certificate id '.$certificate_id);
        $refreshUri = $request->url().'/refresh?keyhash='.$certificate->getPrivateKeyHash();
        $headers = [
                    'Content-Type'            => 'application/x-pem-file',
                    'Content-Length'          => strlen($pem),
                    'Content-Disposition'     => 'filename="certbot.pem"',
                    'Link'                    => '<'.$refreshUri.'>; rel="alternate";',
                    ];

        return response()->make($pem, 200, $headers);
    }

    public function certificateRefreshPEM(Request $request, $account_id, $certificate_id)
    {
        $certificate = $this->certificateType::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        // Alternate authentication mechanism for existing servers to use their key hash to get an updated certificate ONLY
        $keyHash = $request->input('keyhash');
        if ($keyHash != $certificate->getPrivateKeyHash()) {
            abort(401, 'Hash authorization failure for account id '.$account_id.' certificate id '.$certificate_id);
        }
        Log::info('priv key has auth '.$keyHash.' viewed '.$this->accountType.' account id '.$account_id.' certificate id '.$certificate_id);
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
        $certificate = $this->certificateType::where('id', $certificate_id)
                                    ->where('account_id', $account_id)
                                    ->first();
        // Alternate authentication mechanism for existing servers to use their key hash to get an updated certificate ONLY
        $keyHash = $request->input('keyhash');
        if ($keyHash != $certificate->getPrivateKeyHash()) {
            abort(401, 'Hash authorization failure for account id '.$account_id.' certificate id '.$certificate_id);
        }
        Log::info('priv key has auth '.$keyHash.' viewed '.$this->accountType.' account id '.$account_id.' certificate id '.$certificate_id);
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

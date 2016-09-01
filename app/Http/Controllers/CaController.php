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

use App\Ca\Account;
use App\Ca\Certificate;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;

class CaController extends Controller
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
        // Only authenticated users can make these calls
        $this->middleware('jwt.auth');
    }

    public function createAccount(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        if (! $user->can('create', Account::class)) {
            abort(401, 'You are not authorized to create new accounts');
        }
        $account = Account::create($request->all());
        $account->status = 'new';



        $response = [
                    'success' => true,
                    'message' => '',
                    'request' => $request->all(),

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
                    'message'    => 'CA account id '.$account_id.' successfully deleted',
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
        ||  $user->can('read', $certificate)) {
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
        $certificate = Certificate::findOrFail($certificate_id);
        if (! $this->viewAuthorizedCertificate($user, $account, $certificate)) {
            abort(401, 'You are not authorized to access account id '.$account_id.' certificate id '.$certificate_id);
        }
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

        // TODO: make sure each top level domain in this cert are in the permitted zone list for this account








		$req = $request->all();
		// if they pass us a STRING with commas rather than array, just handle that silently.
		if (!is_array($req['subjects']) && strpos($req['subjects'], ',') !== FALSE) {
			$req['subjects'] = explode(',', $req['subjects']);
		}

        $certificate = $account->certificates()->create($req);
//      $certificate->generateKeys();

        // Send back everything
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
        &&  ! $user->can('delete', $certificate)) {
            abort(401, 'You are not authorized to delete certificate for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $certificate->delete();
        $response = [
                    'success'    => true,
                    'message'    => 'CA certificate id '.$certificate_id.' successfully deleted',
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
        &&  ! $user->can('sign', $certificate)) {
            abort(401, 'You are not authorized to sign requests for account id '.$account_id.' certificate id '.$certificate_id);
        }
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
        &&  ! $user->can('sign', $certificate)) {
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
            abort(401, 'You are not authorized to generate certificate signing requests for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $password = $request->input('password');
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
            abort(401, 'You are not authorized to generate certificate signing requests for account id '.$account_id.' certificate id '.$certificate_id);
        }
        $pem = $certificate->privatekey.PHP_EOL
             .$certificate->certificate.PHP_EOL
             .$certificate->chain.PHP_EOL;
        $headers = [
                    'Content-Type'            => 'application/x-pkcs12',
                    'Content-Length'          => strlen($pem),
                    'Content-Disposition'     => 'filename="certbot.pem"',
                    ];

        return response()->make($pem, 200, $headers);
    }
}

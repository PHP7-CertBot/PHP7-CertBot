<?php

namespace App\Http\Controllers;

use App\Acme\Account;
use App\Acme\Certificate;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

use Tymon\JWTAuth\Facades\JWTAuth;

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
        $this->middleware('jwt.auth');
    }

    public function createAccount(Request $request)
	{
		$user = JWTAuth::parseToken()->authenticate();
		if (!$user->can('manage', Account::class)) {
			abort(401, 'You are not authorized to create new accounts');
		}
        $account = Account::create( $request->all() );
		$account->status = "new";
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

    public function deleteAccount($account_id) {
		$user = JWTAuth::parseToken()->authenticate();
		if (!$user->can('manage', Account::class)) {
			abort(401, 'You are not authorized to delete account id ' . $account_id);
		}
        $account = Account::find($account_id);
        $account->delete();
		$response = [
					'success' => true,
					'message' => 'ACME account id ' . id . ' successfully deleted',
					'deleted_at' => $account->deleted_at];
        return response()->json($response);
    }

	public function viewAuthorizedAccount($user, $account) {
		if ($user->can('manage', $account)) {
			return $account;
		}
		// this function actually works by REFERENCE...
		// filtering these changes the account object passed to it!
		if ($user->can('sign',    $account)
		||	$user->can('operate', $account) ){
			$account->privatekey = 'HIDDEN';

			return $account;
		}
		return false;
	}

	// This handles both account level privileges and individual cert level permissions
	public function viewAuthorizedCertificate($user, $account, $certificate) {
		if ($user->can('manage',	$account)
		||	$user->can('sign',		$account)
		||	$user->can('operate',	$account)
		||	$user->can('sign',		$certificate)
		||	$user->can('operate',	$certificate) ){
			return $certificate;
		}
		return false;
	}

	public function listAccounts() {
		$user = JWTAuth::parseToken()->authenticate();
		$accounts = Account::all();
		$show = [];
		foreach ($accounts as $account) {
			if ($this->viewAuthorizedAccount($user, $account)) {
				// hide the following fields from the account list view
				unset($account->publickey);
				unset($account->privatekey);
				unset($account->acmelicense);
				unset($account->authpass);
				unset($account->registration);
				unset($account->deleted_at);
				$show[] = $account;
			}
		}
		$response = [
					'success' => true,
					'message' => '',
					'accounts' => $show,
					];
		return response()->json($response);
    }

    public function getAccount($account_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		if (!$this->viewAuthorizedAccount($user, $account)) {
			abort(401, 'You are not authorized to access account id ' . $account_id);
		}
		$response = [
					'success' => true,
					'message' => '',
					'account' => $account,
					];
		return response()->json($response);
    }

    public function registerAccount($account_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		if (!$user->can('manage', $account)) {
			abort(401, 'You are not authorized to register account id ' . $account_id);
		}
		$response = [];
		try {
			$response['account'] = $account;
			$response['acme'] = $account->postNewReg();
			$response['success'] = true;
			$response['message'] = 'registered account to acme ca for id ' . $account->id;
		} catch (\Exception $e) {
			$response['success'] = false;
			$response['message'] = 'encountered exception: ' . $e->getMessage();
		}
		return response()->json($response);
    }

    public function updateAccountRegistration($account_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		if (!$user->can('manage', $account)) {
			abort(401, 'You are not authorized to register account id ' . $account_id);
		}
		$response = [];
		try {
			$response['account'] = $account;
			$response['acme'] = $account->postUpdateReg();
			$response['success'] = true;
			$response['message'] = 'updated registered account to acme ca for id ' . $account->id;
		} catch (\Exception $e) {
			$response['success'] = false;
			$response['message'] = 'encountered exception: ' . $e->getMessage();
		}
		return response()->json($response);
    }

    public function updateAccount(Request $request, $account_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		if (!$user->can('manage', $account)) {
			abort(401, 'You are not authorized to update account id ' . $account_id);
		}
		$account->fill( $request->all() );
        $account->save();
		$response = [
					'success' => true,
					'message' => '',
					'request' => $request->all(),
					'account' => $account,
					];
		return response()->json($response);
    }

	public function listCertificates($account_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		$certificates = Certificate::where('account_id', $account_id)->get();
		$show = [];
		foreach($certificates as $certificate) {
			if($this->viewAuthorizedCertificate($user, $account, $certificate)) {
				// Hide the following things from the list view
				//unset($certificate->account_id);
				unset($certificate->publickey);
				unset($certificate->privatekey);
				unset($certificate->request);
				unset($certificate->certificate);
				unset($certificate->chain);
				unset($certificate->deleted_at);
				$show[] = $certificate;
			}
		}
		$response = [
					'success' => true,
					'message' => '',
					'certificates' => $show,
					];
		return response()->json($response);
	}

	public function getCertificate($account_id, $certificate_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		if (!$this->viewAuthorizedCertificate($user, $account, $certificate)) {
			abort(401, 'You are not authorized to access account id ' . $account_id . ' certificate id ' . $certificate_id);
		}
		$response = [
					'success' => true,
					'message' => '',
					'certificate' => $certificate,
					];
		return response()->json($response);
	}

    public function createCertificate(Request $request, $account_id)
	{
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		if (!$this->viewAuthorizedAccount($user, $account)) {
			abort(401, 'You are not authorized to create certificates for account id ' . $account_id);
		}

		// make sure each top level domain in this cert are in the permitted zone list for this account
		$allowedzones = \metaclassing\Utility::stringToArray($account->zones);
		$subjects = $request->input('subjects');
		foreach(\metaclassing\Utility::stringToArray($subjects) as $subject) {
			$topleveldomain = \metaclassing\Utility::subdomainToDomain($subject);
			if (!in_array($topleveldomain, $allowedzones)) {
				throw new \Exception('domain ' . $subject . ' tld ' . $topleveldomain . ' is not in this accounts list of permitted zones: ' . $account->zones);
			}
		}

		$certificate = $account->certificates()->create( $request->all() );
		$certificate->generateKeys();

		// Send back everything
		$response = [
					'success' => true,
					'message' => '',
					'request' => $request->all(),
					'certificate' => $certificate,
					];
		return response()->json($response);
    }

	public function certificateGenerateRequest($account_id, $certificate_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		if (!$this->viewAuthorizedCertificate($user, $account, $certificate)) {
			abort(401, 'You are not authorized to generate certificate signing requests for account id ' . $account_id . ' certificate id ' . $certificate_id);
		}
		$certificate->generateRequest();
		// Send back everything
		$response = [
					'success' => true,
					'message' => 'generated new signing request for cert id ' . $certificate_id,
					'certificate' => $certificate,
					];
		return response()->json($response);
	}

	public function certificateSign($account_id, $certificate_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		if (!$user->can('sign', $account)
		&&	!$user->can('sign', $certificate) ){
			abort(401, 'You are not authorized to sign requests for account id ' . $account_id . ' certificate id ' . $certificate_id);
		}
		$response = [];
		try {
			$account->signCertificate($certificate);
			$response['success'] = 'true';
			$response['message'] = 'signed certificate id ' . $certificate->id;
			$response['log'] = $account->log();
		} catch (\Exception $e) {
			$response['success'] = false;
			$response['message'] = 'encountered exception: ' . $e->getMessage();
			$response['log'] = $account->log();
		}
		return response()->json($response);
	}

	public function certificateRenew($account_id, $certificate_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		if (!$user->can('sign', $account)
		&&	!$user->can('sign', $certificate) ){
			abort(401, 'You are not authorized to sign requests for account id ' . $account_id . ' certificate id ' . $certificate_id);
		}
		$response = [];
		try {
			$account->renewCertificate($certificate);
			$response['success'] = 'true';
			$response['message'] = 'renewed certificate id ' . $certificate->id;
			$response['log'] = $account->log();
		} catch (\Exception $e) {
			$response['success'] = false;
			$response['message'] = 'encountered renew exception: ' . $e->getMessage();
			$response['log'] = $account->log();
		}
		return response()->json($response);
	}

	public function certificateDownloadPKCS12(Request $request, $account_id, $certificate_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		if (!$this->viewAuthorizedCertificate($user, $account, $certificate)) {
			abort(401, 'You are not authorized to generate certificate signing requests for account id ' . $account_id . ' certificate id ' . $certificate_id);
		}
		$password = $request->input('password');
		$pkcs12 = $certificate->generateDownloadPKCS12($password);
		$headers = [
					'Content-Type'			=> 'application/x-pkcs12',
					'Content-Length'		=> strlen($pkcs12),
					'Content-Disposition'	=> 'filename="certbot.p12"'
					];
		return response()->make($pkcs12, 200, $headers);
	}

	public function certificateDownloadPEM(Request $request, $account_id, $certificate_id) {
		$user = JWTAuth::parseToken()->authenticate();
		$account = Account::find($account_id);
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		if (!$this->viewAuthorizedCertificate($user, $account, $certificate)) {
			abort(401, 'You are not authorized to generate certificate signing requests for account id ' . $account_id . ' certificate id ' . $certificate_id);
		}
		$pem = $certificate->privatekey . PHP_EOL
			 . $certificate->certificate . PHP_EOL
			 . $certificate->chain . PHP_EOL;
		$headers = [
					'Content-Type'			=> 'application/x-pkcs12',
					'Content-Length'		=> strlen($pem),
					'Content-Disposition'	=> 'filename="certbot.pem"'
					];
		return response()->make($pem, 200, $headers);
	}

}

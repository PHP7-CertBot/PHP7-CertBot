<?php

namespace App\Http\Controllers;

use App\Account;
use App\Certificate;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

use Tymon\JWTAuth\Facades\JWTAuth;

class AccountController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | ACME account controller
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
		// I assume this will never fail
        $account = Account::create( $request->all() );
		$account->status = "new";
		// I assume this will never fail
		$account->generateKeys();
		// This however might fail and I need to figure out wtf to do
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

	public function listAccounts() {
		$accounts = Account::all();
		$response = [
					'success' => true,
					'message' => '',
					'accounts' => $accounts,
					];
		return response()->json($response);
    }

    public function getAccount($account_id) {
		$account = Account::find($account_id);
		$response = [
					'success' => true,
					'message' => '',
					'account' => $account,
					];
		return response()->json($response);
    }

    public function registerAccount($account_id) {
		$response = [];
		try {
			$account = Account::find($account_id);
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
		$response = [];
		try {
			$account = Account::find($account_id);
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

    public function debugAccount(Request $request, $account_id) {
		return $this->certificateUpdateExpiration(1, 1);
		// save our log files for debugging
		$acmelogfile = storage_path('logs/acmeclient.log');
		$acme = file_get_contents($acmelogfile);
		$response = [$acmelogfile => $acme];
		$response = \metaclassing\Utility::encodeArrayUTF($response);
		return response()->json( $response );
/*		$account = Account::find($account_id);

		$response = [
					'success' => true,
					'message' => '',
					'request' => $request->all(),
					'account' => $account,
					];
		return response()->json($response);/**/
    }

    public function getAccountPublicKey($account_id) {
		$account = Account::find($account_id);
		return $account->publickey . PHP_EOL;
		$response = [
					'success' => true,
					'message' => '',
					'account' => $account,
					'publickey' => $account->publickey,
					];
		return \metaclassing\Utility::encodeJson($response);
    }

    public function deleteAccount($account_id) {
        $account = Account::find($account_id);
        $account->delete();
		$response = [
					'success' => true,
					'message' => 'ACME account id ' . id . ' successfully deleted',
					'deleted_at' => $account->deleted_at];
        return response()->json($response);
    }

    public function updateAccount(Request $request, $account_id) {
		$account = Account::find($account_id);
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
		$account = Account::find($account_id);
		$certificates = Certificate::where('account_id', $account_id)->get();
		$response = [
					'success' => true,
					'message' => '',
					'certificates' => $certificates,
					];
		return response()->json($response);
	}

    public function createCertificate(Request $request, $account_id)
	{
		$account = Account::find($account_id);

		// make sure each top level domain in this cert are in the permitted zone list for this account
		$allowedzones = \metaclassing\Utility::stringToArray($account->zones);
		$domains = $request->input('domains');
		foreach(\metaclassing\Utility::stringToArray($domains) as $domain) {
			$topleveldomain = \metaclassing\Utility::subdomainToDomain($domain);
			if (!in_array($topleveldomain, $allowedzones)) {
				throw new \Exception('domain ' . $domain . ' tld ' . $topleveldomain . ' is not in this accounts list of permitted zones: ' . $account->zones);
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

	public function certificateDomains($account_id, $certificate_id) {
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		$domains = $certificate->domainsArray();
		$response = [
					'success' => true,
					'message' => '',
					'domains' => $domains,
					];
		return response()->json($response);
	}

	public function certificateGenerateKeys($account_id, $certificate_id) {
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		$certificate->generateKeys();
		// Send back everything
		$response = [
					'success' => true,
					'message' => 'generating new keys for cert id ' . $certificate_id,
					'certificate' => $certificate,
					];
		return response()->json($response);
	}

	public function certificateUpdateExpiration($account_id, $certificate_id) {
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		$expires = $certificate->updateExpirationDate();
		$response = [
            'success' => true,
            'message' => '',
            'certificate' => $certificate,
            ];
		return response()->json($response);
	}

	public function certificateGenerateRequest($account_id, $certificate_id) {
		$certificate = Certificate::where('id', $certificate_id)
									->where('account_id', $account_id)
									->first();
		$certificate->generateRequest();
		// Send back everything
		$response = [
					'success' => true,
					'message' => 'generating new keys for cert id ' . $certificate_id,
					'certificate' => $certificate,
					];
		return response()->json($response);
	}

	public function certificateSign($account_id, $certificate_id) {
		$response = [];
		try {
			$account = Account::find($account_id);
			$certificate = Certificate::find($certificate_id);
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

	public function certificateDownloadPKCS12(Request $request, $account_id, $certificate_id) {
		$account = Account::find($account_id);
		$certificate = Certificate::find($certificate_id);
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
		$account = Account::find($account_id);
		$certificate = Certificate::find($certificate_id);
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

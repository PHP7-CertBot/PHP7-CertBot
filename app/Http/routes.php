<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It's a breeze. Simply tell Laravel the URIs it should respond to
| and give it the controller to call when that URI is requested.
|
*/

Route::get('/', function () {
    return view('welcome');
});

$api = app('Dingo\Api\Routing\Router');

$api->version('v1', function($api) {
	$api->get('hello', function() {
		return "Hello world!\n";
	});
	// This spits back a JWT to authenticate additional API calls.
	$api->get('authenticate', 'App\Http\Controllers\Auth\AuthController@authenticate');
	$api->get('userinfo', 'App\Http\Controllers\Auth\AuthController@userinfo');

	// This is all the ACME calls for acconuts, certs, etc.
	$api->group(['prefix' => 'acme','namespace' => 'App\Http\Controllers'], function($api) {
		// Account management routes
		$api->group(['prefix' => 'account'], function($api) {
			$controller = 'AcmeController';
		    $api->get	('',						$controller.'@listAccounts'					);
		    $api->get	('/{id}',					$controller.'@getAccount'					);
		    $api->post	('',						$controller.'@createAccount'				);
		    $api->put	('/{id}',					$controller.'@updateAccount'				);
		    $api->delete('/{id}',					$controller.'@deleteAccount'				);
		    $api->get	('/{id}/register',			$controller.'@registerAccount'				);
		    $api->get	('/{id}/updatereg',			$controller.'@updateAccountRegistration'	);
		    $api->get	('/{id}/debug',				$controller.'@debug'						);
		    $api->post	('/{id}/debug',				$controller.'@debug'						);
		});
		// Certificate management routes under an account id
		$api->group(['prefix' => 'account/{account_id}/certificate'], function($api) {
			$controller = 'AcmeController';
		    $api->get	('',						$controller.'@listCertificates'				);
		    $api->get	('/{id}',					$controller.'@getCertificate'				);
		    $api->post	('',						$controller.'@createCertificate'			);
		    $api->get	('/{id}/subjects',			$controller.'@certificateSubjects'			);
		    $api->get	('/{id}/generatekeys',		$controller.'@certificateGenerateKeys'		);
		    $api->get	('/{id}/generaterequest',	$controller.'@certificateGenerateRequest'	);
		    $api->get	('/{id}/sign',				$controller.'@certificateSign'				);
		    $api->get	('/{id}/renew',				$controller.'@certificateRenew'				);
		    $api->get	('/{id}/pkcs12',			$controller.'@certificateDownloadPKCS12'	);
		    $api->get	('/{id}/pem',				$controller.'@certificateDownloadPEM'		);
		});
	});

	// This is all the CA calls for accounts, certs, etc.
	$api->group(['prefix' => 'ca','namespace' => 'App\Http\Controllers'], function($api) {
		// Account management routes
		$api->group(['prefix' => 'account'], function($api) {
			$controller = 'CaController';
		    $api->get	('',						$controller.'@listAccounts'					);
		    $api->get	('/{id}',					$controller.'@getAccount'					);
		    $api->post	('',						$controller.'@createAccount'				);
		    $api->put	('/{id}',					$controller.'@updateAccount'				);
		    $api->delete('/{id}',					$controller.'@deleteAccount'				);
		    $api->get	('/{id}/debug',				$controller.'@debug'						);
		    $api->post	('/{id}/debug',				$controller.'@debug'						);
		});
		// Certificate management routes under an account id
		$api->group(['prefix' => 'account/{account_id}/certificate'], function($api) {
			$controller = 'CaController';
		    $api->get	('',						$controller.'@listCertificates'				);
		    $api->get	('/{id}',					$controller.'@getCertificate'				);
		    $api->post	('',						$controller.'@createCertificate'			);
		    $api->get	('/{id}/subjects',			$controller.'@certificateSubjects'			);
		    $api->get	('/{id}/generatekeys',		$controller.'@certificateGenerateKeys'		);
		    $api->get	('/{id}/generaterequest',	$controller.'@certificateGenerateRequest'	);
		    $api->get	('/{id}/sign',				$controller.'@certificateSign'				);
		    $api->get	('/{id}/renew',				$controller.'@certificateRenew'				);
		    $api->get	('/{id}/pkcs12',			$controller.'@certificateDownloadPKCS12'	);
		    $api->get	('/{id}/pem',				$controller.'@certificateDownloadPEM'		);
		});
	});
});

//Route::auth();

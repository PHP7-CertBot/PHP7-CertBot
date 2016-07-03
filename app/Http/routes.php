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
	$api->get('phpinfo', function() {
		phpinfo();
	});
	// This spits back a JWT to authenticate additional API calls.
	$api->get('authenticate', 'App\Http\Controllers\Auth\AuthController@authenticate');
	$api->get('userinfo', 'App\Http\Controllers\Auth\AuthController@userinfo');

	// This is all the ACME calls for acconuts, certs, etc.
	$api->group(['prefix' => 'acme','namespace' => 'App\Http\Controllers'], function($api) {
		// Account management calls
	    $api->get('account','AccountController@listAccounts');
	    $api->get('account/{id}','AccountController@getAccount');
	    $api->get('account/{id}/pubkey','AccountController@getAccountPublicKey');
	    $api->post('account','AccountController@createAccount');
	    $api->put('account/{id}','AccountController@updateAccount');
	    $api->delete('account/{id}','AccountController@deleteAccount');

	    $api->get('account/{id}/register','AccountController@registerAccount');
	    $api->get('account/{id}/updatereg','AccountController@updateAccountRegistration');

	    $api->get('account/{id}/debug','AccountController@debugAccount');
	    $api->post('account/{id}/debug','AccountController@debugAccount');

		// Certificate management calls
	    $api->get('account/{id}/certificate','AccountController@listCertificates');
	    $api->post('account/{id}/certificate','AccountController@createCertificate');
	    $api->get('account/{id}/certificate/{certid}/domains','AccountController@certificateDomains');
	    $api->get('account/{id}/certificate/{certid}/generatekeys','AccountController@certificateGenerateKeys');
	    $api->get('account/{id}/certificate/{certid}/generaterequest','AccountController@certificateGenerateRequest');
	    $api->get('account/{id}/certificate/{certid}/sign','AccountController@certificateSign');

	    $api->get('account/{id}/certificate/{certid}/pkcs12','AccountController@certificateDownloadPKCS12');
	    $api->get('account/{id}/certificate/{certid}/pem','AccountController@certificateDownloadPEM');
	});
});

//Route::auth();

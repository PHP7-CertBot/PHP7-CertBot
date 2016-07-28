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

$api->version('v1', function ($api) {
    /*
     * @SWG\Info(title="Certbot API", version="0.1")
     */

    /*
     * @SWG\Get(
     *     path="/api/hello",
     *     @SWG\Response(response="200", description="Hello world example")
     * )
     */

    $api->get('hello', function () {
        return "Hello world!\n";
    });

    /*
     * @SWG\Get(
     *     path="/api/authenticate",
     *     @SWG\Response(response="200", description="Get users JSON web token by TLS client certificate authentication")
     * )
     */
    // This spits back a JWT to authenticate additional API calls.
    $api->get('authenticate', 'App\Http\Controllers\Auth\AuthController@authenticate');
    /*
     * @SWG\Post(
     *     path="/api/authenticate",
     *     @SWG\Response(response="200", description="Get users JSON web token by LDAP username and password")
     * )
     */
    $api->post('authenticate', 'App\Http\Controllers\Auth\AuthController@authenticate');
    /*
     * @SWG\Get(
     *     path="/api/userinfo",
     *     @SWG\Response(response="200", description="Get users full LDAP record by sending their JSON web token")
     * )
     */
    $api->get('userinfo', 'App\Http\Controllers\Auth\AuthController@userinfo');

    // This is all the ACME calls for acconuts, certs, etc.
    $api->group(['prefix' => 'acme', 'namespace' => 'App\Http\Controllers'], function ($api) {
        // Account management routes
        $api->group(['prefix' => 'account'], function ($api) {
            $controller = 'AcmeController';
            $api->get('', $controller.'@listAccounts');
            $api->post('', $controller.'@createAccount');
            $api->get('/{id}', $controller.'@getAccount');
            $api->put('/{id}', $controller.'@updateAccount');
            $api->delete('/{id}', $controller.'@deleteAccount');
            $api->get('/{id}/register', $controller.'@registerAccount');
            $api->get('/{id}/updatereg', $controller.'@updateAccountRegistration');
        });
        // Certificate management routes under an account id
        $api->group(['prefix' => 'account/{account_id}/certificate'], function ($api) {
            $controller = 'AcmeController';
            $api->get('', $controller.'@listCertificates');
            $api->post('', $controller.'@createCertificate');
            $api->get('/{id}', $controller.'@getCertificate');
            $api->put('/{id}', $controller.'@updateCertificate');
            $api->delete('/{id}', $controller.'@deleteCertificate');
            $api->get('/{id}/generatekeys', $controller.'@certificateGenerateKeys');
            $api->get('/{id}/generaterequest', $controller.'@certificateGenerateRequest');
            $api->get('/{id}/sign', $controller.'@certificateSign');
            $api->get('/{id}/renew', $controller.'@certificateRenew');
            $api->get('/{id}/pkcs12', $controller.'@certificateDownloadPKCS12');
            $api->get('/{id}/pem', $controller.'@certificateDownloadPEM');
        });
    });

    // This is all the CA calls for accounts, certs, etc.
    $api->group(['prefix' => 'ca', 'namespace' => 'App\Http\Controllers'], function ($api) {
        // Account management routes
        $api->group(['prefix' => 'account'], function ($api) {
            $controller = 'CaController';
            $api->get('', $controller.'@listAccounts');
            $api->post('', $controller.'@createAccount');
            $api->get('/{id}', $controller.'@getAccount');
            $api->put('/{id}', $controller.'@updateAccount');
            $api->delete('/{id}', $controller.'@deleteAccount');
        });
        // Certificate management routes under an account id
        $api->group(['prefix' => 'account/{account_id}/certificate'], function ($api) {
            $controller = 'CaController';
            $api->get('', $controller.'@listCertificates');
            $api->post('', $controller.'@createCertificate');
            $api->get('/{id}', $controller.'@getCertificate');
            $api->put('/{id}', $controller.'@updateCertificate');
            $api->delete('/{id}', $controller.'@deleteCertificate');
            $api->get('/{id}/generatekeys', $controller.'@certificateGenerateKeys');
            $api->get('/{id}/generaterequest', $controller.'@certificateGenerateRequest');
            $api->get('/{id}/sign', $controller.'@certificateSign');
            $api->get('/{id}/renew', $controller.'@certificateRenew');
            $api->get('/{id}/pkcs12', $controller.'@certificateDownloadPKCS12');
            $api->get('/{id}/pem', $controller.'@certificateDownloadPEM');
        });
    });
});

//Route::auth();

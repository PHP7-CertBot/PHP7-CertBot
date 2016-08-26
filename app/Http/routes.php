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
     **/

    /*
     * @SWG\Get(
     *     path="/api/hello",
     *     @SWG\Response(response="200", description="Hello world example")
     * )
     **/
    $api->any('hello', function (Illuminate\Http\Request $request) {
        return 'Hello '.$request->method().PHP_EOL;
    });
    $api->addRoute('SIGN', 'hello', function (Illuminate\Http\Request $request) {
        return 'Hello SIGN'.PHP_EOL;
    });

    $api->group(['prefix' => 'authenticate', 'namespace' => 'App\Http\Controllers\Auth'], function ($api) {
	    /*
	     * @SWG\Get(
	     *     path="/api/authenticate",
	     *     @SWG\Response(response="200", description="Get users JSON web token by TLS client certificate authentication")
	     * )
	     **/
	    // This spits back a JWT to authenticate additional API calls.
	    $api->get('', 'AuthController@authenticate');
	    /*
	     * @SWG\Post(
	     *     path="/api/authenticate",
         *     @SWG\Parameter(
         *         name="username",
         *         in="query",
         *         description="LDAP username",
         *         required=true,
         *         type="string"
         *     ),
         *     @SWG\Parameter(
         *         name="password",
         *         in="query",
         *         description="LDAP password",
         *         required=true,
         *         type="string"
         *     ),
	     *     @SWG\Response(response="200", description="Get users JSON web token by LDAP username and password")
	     * )
	     **/
	    $api->post('', 'AuthController@authenticate');
	});

    // This is all the ACME calls for acconuts, certs, etc.
    $api->group(['prefix' => 'acme', 'namespace' => 'App\Http\Controllers', 'middleware' => 'api.auth'], function ($api) {
        // Account management routes
        $api->group(['prefix' => 'accounts'], function ($api) {
            $controller = 'AcmeController';
            /*
             * @SWG\Get(
             *     path="/api/acme/accounts",
             *     summary="List available ACME accounts for authorized user",
             *     description="",
             *     operationId="listAcmeAccounts",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/AcmeAccount")
             *         ),
             *     ),
             *     @SWG\Response(
             *         response="401",
             *         description="Unauthorized user",
             *     ),
             *     security={
             *         {
             *              "token": {}
             *         }
             *     }
             * )
             */
            $api->get('', $controller.'@listAccounts');
            /*
             * @SWG\Post(
             *     path="/api/acme/accounts",
             *     summary="Create new ACME account",
             *     description="",
             *     operationId="createAcmeAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/AcmeAccount")
             *         ),
             *     ),
             *     @SWG\Response(
             *         response="401",
             *         description="Unauthorized user",
             *     ),
             *     security={
             *         {
             *             "token": {}
             *         }
             *     }
             * )
             */
            $api->post('', $controller.'@createAccount');
            /*
             * @SWG\Get(
             *     path="/api/acme/accounts/{account_id}",
             *     summary="Find available ACME account by account ID",
             *     description="",
             *     operationId="getAcmeAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/AcmeAccount")
             *         ),
             *     ),
             *     @SWG\Response(
             *         response="401",
             *         description="Unauthorized user",
             *     ),
             *     security={
             *         {
             *             "token": {}
             *         }
             *     }
             * )
             */
            $api->get('/{id}', $controller.'@getAccount');
            /*
             * @SWG\Put(
             *     path="/api/acme/accounts/{account_id}",
             *     summary="Update ACME account by account ID",
             *     description="",
             *     operationId="updateAcmeAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/AcmeAccount")
             *         ),
             *     ),
             *     @SWG\Response(
             *         response="401",
             *         description="Unauthorized user",
             *     ),
             *     security={
             *         {
             *             "token": {}
             *         }
             *     }
             * )
             */
            $api->put('/{id}', $controller.'@updateAccount');
            /*
             * @SWG\Delete(
             *     path="/api/acme/accounts/{account_id}",
             *     summary="Delete ACME account by account ID",
             *     description="",
             *     operationId="deleteAcmeAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *     ),
             *     @SWG\Response(
             *         response="401",
             *         description="Unauthorized user",
             *     ),
             *     security={
             *         {
             *             "token": {}
             *         }
             *     }
             * )
             */
            $api->delete('/{id}', $controller.'@deleteAccount');
            /*
             * @SWG\Post(
             *     path="/api/acme/accounts/{account_id}/register",
             *     summary="Register ACME account with ACME authority by account ID",
             *     description="",
             *     operationId="registerAcmeAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *     ),
             *     @SWG\Response(
             *         response="401",
             *         description="Unauthorized user",
             *     ),
             *     security={
             *         {
             *             "token": {}
             *         }
             *     }
             * )
             */
            $api->post('/{id}/register', $controller.'@registerAccount');
            /*
             * @SWG\Put(
             *     path="/api/acme/accounts/{account_id}/register",
             *     summary="Update ACME account registration with ACME authority by account ID",
             *     description="",
             *     operationId="updateRegAcmeAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *     ),
             *     @SWG\Response(
             *         response="401",
             *         description="Unauthorized user",
             *     ),
             *     security={
             *         {
             *             "token": {}
             *         }
             *     }
             * )
             */
            $api->put('/{id}/register', $controller.'@updateAccountRegistration');
        });
        // Certificate management routes under an account id
        $api->group(['prefix' => 'accounts/{account_id}/certificates', 'middleware' => 'api.auth'], function ($api) {
            $controller = 'AcmeController';
            $api->get('', $controller.'@listCertificates');
            $api->post('', $controller.'@createCertificate');
            $api->get('/{id}', $controller.'@getCertificate');
            $api->put('/{id}', $controller.'@updateCertificate');
            $api->delete('/{id}', $controller.'@deleteCertificate');
            $api->post('/{id}/generatekeys', $controller.'@certificateGenerateKeys');
            $api->post('/{id}/generaterequest', $controller.'@certificateGenerateRequest');
            $api->post('/{id}/sign', $controller.'@certificateSign');
            $api->post('/{id}/renew', $controller.'@certificateRenew');
            $api->get('/{id}/pkcs12', $controller.'@certificateDownloadPKCS12');
            $api->get('/{id}/pem', $controller.'@certificateDownloadPEM');
        });
    });

    // This is all the CA calls for accounts, certs, etc.
    $api->group(['prefix' => 'ca', 'namespace' => 'App\Http\Controllers', 'middleware' => 'api.auth'], function ($api) {
        // Account management routes
        $api->group(['prefix' => 'accounts'], function ($api) {
            $controller = 'CaController';
            $api->get('', $controller.'@listAccounts');
            $api->post('', $controller.'@createAccount');
            $api->get('/{id}', $controller.'@getAccount');
            $api->put('/{id}', $controller.'@updateAccount');
            $api->delete('/{id}', $controller.'@deleteAccount');
        });
        // Certificate management routes under an account id
        $api->group(['prefix' => 'accounts/{account_id}/certificates', 'middleware' => 'api.auth'], function ($api) {
            $controller = 'CaController';
            $api->get('', $controller.'@listCertificates');
            $api->post('', $controller.'@createCertificate');
            $api->get('/{id}', $controller.'@getCertificate');
            $api->put('/{id}', $controller.'@updateCertificate');
            $api->delete('/{id}', $controller.'@deleteCertificate');
            $api->post('/{id}/generatekeys', $controller.'@certificateGenerateKeys');
            $api->post('/{id}/generaterequest', $controller.'@certificateGenerateRequest');
            $api->post('/{id}/sign', $controller.'@certificateSign');
            $api->post('/{id}/renew', $controller.'@certificateRenew');
            $api->get('/{id}/pkcs12', $controller.'@certificateDownloadPKCS12');
            $api->get('/{id}/pem', $controller.'@certificateDownloadPEM');
        });
    });
});

//Route::auth();

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
    /**
     * @SWG\Info(title="Certbot API", version="0.1")
     **/

    /**
     * @SWG\Get(
     *     path="/api/hello",
     *     summary="Hello world test for API troubleshooting",
     *     @SWG\Response(response="200", description="Hello world example")
     * )
     **/
    $api->any('hello', function (Illuminate\Http\Request $request) {
        return 'Hello '.$request->method().PHP_EOL;
    });

    $api->group(['prefix' => 'authenticate', 'namespace' => 'App\Http\Controllers\Auth'], function ($api) {
        /**
         * @SWG\Get(
         *     path="/api/authenticate",
         *     summary="Get JSON web token by TLS client certificate authentication",
         *     @SWG\Response(
         *         response=200,
         *         description="Authentication succeeded",
         *         ),
         *     ),
         * )
         **/
        $api->get('', 'AuthController@authenticate');
        /**
         * @SWG\Post(
         *     path="/api/authenticate",
         *     summary="Get JSON web token by LDAP user authentication",
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
         *     @SWG\Response(
         *         response=200,
         *         description="Authentication succeeded",
         *         ),
         *     ),
         * )
         **/
        $api->post('', 'AuthController@authenticate');
    });

    // This is all the ACME calls for acconuts, certs, etc.
    $api->group(['prefix' => 'acme', 'namespace' => 'App\Http\Controllers', 'middleware' => 'api.auth'], function ($api) {
        // Account management routes
        $api->group(['prefix' => 'accounts'], function ($api) {
            $controller = 'AcmeController';
            /**
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
             *     security={
             *         {
             *              "token": {}
             *         }
             *     }
             * )
             */
            $api->get('', $controller.'@listAccounts');
            /**
             * @SWG\Post(
             *     path="/api/acme/accounts",
             *     summary="Create new ACME account",
             *     description="",
             *     operationId="createAcmeAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="name",
             *         in="query",
             *         description="name of new account",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="contact",
             *         in="query",
             *         description="email contact for account",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="acmecaurl",
             *         in="query",
             *         description="base url to ACME certificate authority",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="acmelicense",
             *         in="query",
             *         description="url of ACME cert authority license agreement",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authtype",
             *         in="query",
             *         description="authentication type for acme challenges",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authprovider",
             *         in="query",
             *         description="provider for auth type",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authuser",
             *         in="query",
             *         description="user for auth provider",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authpass",
             *         in="query",
             *         description="pass for authprovider",
             *         required=false,
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
            $api->post('', $controller.'@createAccount');
            /**
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
             *         type="integer"
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
            /**
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
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="name",
             *         in="query",
             *         description="name of new account",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="contact",
             *         in="query",
             *         description="email contact for account",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="acmecaurl",
             *         in="query",
             *         description="base url to ACME certificate authority",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="acmelicense",
             *         in="query",
             *         description="url of ACME cert authority license agreement",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authtype",
             *         in="query",
             *         description="authentication type for acme challenges",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authprovider",
             *         in="query",
             *         description="provider for auth type",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authuser",
             *         in="query",
             *         description="user for auth provider",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authpass",
             *         in="query",
             *         description="pass for authprovider",
             *         required=false,
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
            /**
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
             *         type="integer"
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
            /**
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
             *         type="integer"
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
            /**
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
             *         type="integer"
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
            /**
             * @SWG\Get(
             *     path="/api/acme/accounts/{account_id}/certificates",
             *     summary="List available certificates in an ACME account",
             *     description="",
             *     operationId="listCertificates",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/AcmeCertificate")
             *         ),
             *     ),
             *     security={
             *         {
             *              "token": {}
             *         }
             *     }
             * )
             */
            $api->get('', $controller.'@listCertificates');
            /**
             * @SWG\Post(
             *     path="/api/acme/accounts/{account_id}/certificates",
             *     summary="Create a new certificate in an ACME account",
             *     description="",
             *     operationId="createCertificate",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="name",
             *         in="query",
             *         description="name of new certificate",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="subjects",
             *         in="query",
             *         description="list of subjects for this certificate, first is CN, following are subject alternative names",
             *         required=true,
             *         type="array",
             *         @SWG\Items(
             *             type="string",
             *             description="sibject cn or san ex: sub.domain.com",
             *         ),
             *     ),
             *     @SWG\Parameter(
             *         name="request",
             *         in="query",
             *         description="optional externally generated PKCS10 certificate signing request -----BEGIN CERTIFICATE REQUEST-----\nBASE64\n-----END CERTIFICATE REQUEST-----",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/AcmeCertificate")
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
            $api->post('', $controller.'@createCertificate');
            /**
             * @SWG\Get(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}",
             *     summary="Find certificate in accme account by ID",
             *     description="",
             *     operationId="getCertificate",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="path",
             *         description="ID of certificate in this account",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/AcmeCertificate")
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
            $api->get('/{id}', $controller.'@getCertificate');
            /**
             * @SWG\Put(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}",
             *     summary="Update certificate in account by ID",
             *     description="",
             *     operationId="updateCertificate",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account id",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="path",
             *         description="ID of certificate",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="name",
             *         in="query",
             *         description="name of certificate",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="subjects",
             *         in="query",
             *         description="list of subjects for this certificate, first is CN, following are subject alternative names",
             *         required=false,
             *         type="array",
             *         @SWG\Items(
             *             type="string",
             *             description="sibject cn or san ex: sub.domain.com",
             *         ),
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/AcmeCertificate")
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
            $api->put('/{id}', $controller.'@updateCertificate');
            /**
             * @SWG\Delete(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}",
             *     summary="Delete certificate in account by id",
             *     description="",
             *     operationId="deleteCertificate",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="path",
             *         description="ID of certificate",
             *         required=true,
             *         type="integer"
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
            $api->delete('/{id}', $controller.'@deleteCertificate');
            /**
             * @SWG\Post(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}/generatekeys",
             *     summary="Generate new key pair for certificate",
             *     description="Keypair generation is required if you plan to generate a certificate signing request inside certbot",
             *     operationId="certificateGenerateKeys",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of certificate",
             *         required=true,
             *         type="integer"
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
             *              "token": {}
             *         }
             *     }
             * )
             */
            $api->post('/{id}/generatekeys', $controller.'@certificateGenerateKeys');
            /**
             * @SWG\Post(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}/generaterequest",
             *     summary="Generate new certificate signing request",
             *     description="This is only necessary if you did not load an externally generated CSR into the tool",
             *     operationId="certificateGenerateRequest",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of certificate",
             *         required=true,
             *         type="integer"
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
             *              "token": {}
             *         }
             *     }
             * )
             */
            $api->post('/{id}/generaterequest', $controller.'@certificateGenerateRequest');
            /**
             * @SWG\Post(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}/sign",
             *     summary="Sign this certificates request",
             *     description="You must have signing permissions for the owning account AND a valid CSR for an ACME ca to sign must be provided or generated",
             *     operationId="certificateSign",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of certificate",
             *         required=true,
             *         type="integer"
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
             *              "token": {}
             *         }
             *     }
             * )
             */
            $api->post('/{id}/sign', $controller.'@certificateSign');
            /**
             * @SWG\Post(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}/renew",
             *     summary="Renew this certificate",
             *     description="Before expiration a certificate can be renewed without re-verification provided its request signature has not changed",
             *     operationId="certificateRenew",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of certificate",
             *         required=true,
             *         type="integer"
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
             *              "token": {}
             *         }
             *     }
             * )
             */
            $api->post('/{id}/renew', $controller.'@certificateRenew');
            /**
             * @SWG\Get(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}/pkcs12",
             *     summary="Download a PKCS12 encoded bag including certificate, chain, and private key",
             *     description="",
             *     operationId="certificateDownloadPKCS12",
             *     consumes={"application/json"},
             *     produces={"application/x-pkcs12"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="path",
             *         description="ID of certificate",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="password",
             *         in="query",
             *         description="optional password to encrypt pkcs12 file contents",
             *         required=false,
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
             *              "token": {}
             *         }
             *     }
             * )
             */
            $api->get('/{id}/pkcs12', $controller.'@certificateDownloadPKCS12');
            /**
             * @SWG\Get(
             *     path="/api/acme/accounts/{account_id}/certificates/{certificate_id}/pem",
             *     summary="Download a pem encoded file including certificate, chain, and private key",
             *     description="",
             *     operationId="certificateDownloadPEM",
             *     consumes={"application/json"},
             *     produces={"application/x-pem-file"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account",
             *         required=true,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="path",
             *         description="ID of certificate",
             *         required=true,
             *         type="integer"
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
             *              "token": {}
             *         }
             *     }
             * )
             */
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

<?php

    // This is all the CA calls for accounts, certs, etc.
    $options = [
                   'prefix'     => 'ca',
                   'namespace'  => 'App\Http\Controllers',
                   'middleware' => [
                                       'api.auth',
                                       'api.throttle',
                                   ],
                   'limit'   => 100,
                   'expires' => 5,
               ];
    $api->group($options, function ($api) {
        // Account management routes
        $api->group(['prefix' => 'accounts'], function ($api) {
            $controller = 'CaController';
            /**
             * @SWG\Get(
             *     path="/api/ca/accounts",
             *     tags={"CA Accounts"},
             *     summary="List available CA accounts for authorized user",
             *     description="",
             *     operationId="listAccounts",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/CaAccount")
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
             *     path="/api/ca/accounts",
             *     tags={"CA Accounts"},
             *     summary="Create new CA account",
             *     description="",
             *     operationId="createAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="name",
             *         in="formData",
             *         description="name of new account",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="contact",
             *         in="formData",
             *         description="email contact for account",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="zones",
             *         in="formData",
             *         description="zones this ca is authorized to issue certificates for",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="formData",
             *         description="ID number of coresponding certificate object, required for signing operations",
             *         required=false,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="crlurl",
             *         in="formData",
             *         description="fully qualified url to certificate revocation list for this CA",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/CaAccount")
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
             *     path="/api/ca/accounts/{account_id}",
             *     tags={"CA Accounts"},
             *     summary="Find available CA account by account ID",
             *     description="",
             *     operationId="getAccount",
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
             *             @SWG\Items(ref="#/definitions/CaAccount")
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
             *     path="/api/ca/accounts/{account_id}",
             *     tags={"CA Accounts"},
             *     summary="Update CA account by account ID",
             *     description="",
             *     operationId="updateAccount",
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
             *         name="name",
             *         in="formData",
             *         description="name of new account",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="contact",
             *         in="formData",
             *         description="email contact for account",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="zones",
             *         in="formData",
             *         description="zones this ca is authorized to issue certificates for",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="formData",
             *         description="ID number of coresponding certificate object, required for signing operations",
             *         required=false,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="crlurl",
             *         in="formData",
             *         description="fully qualified url to certificate revocation list for this CA",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/CaAccount")
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
             *     path="/api/ca/accounts/{account_id}",
             *     tags={"CA Accounts"},
             *     summary="Delete CA account by account ID",
             *     description="",
             *     operationId="deleteAccount",
             *     consumes={"application/json"},
             *     produces={"application/json"},
             *     @SWG\Parameter(
             *         name="account_id",
             *         in="path",
             *         description="ID of account",
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
        });
        // Certificate management routes under an account id
        $api->group(['prefix' => 'accounts/{account_id}/certificates', 'middleware' => 'api.auth'], function ($api) {
            $controller = 'CaController';
            /**
             * @SWG\Get(
             *     path="/api/ca/accounts/{account_id}/certificates",
             *     tags={"CA Certificates"},
             *     summary="List available certificates in an CA account",
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
             *             @SWG\Items(ref="#/definitions/CaCertificate")
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
             *     path="/api/ca/accounts/{account_id}/certificates",
             *     tags={"CA Certificates"},
             *     summary="Create a new certificate in an CA account",
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
             *         in="formData",
             *         description="name of new certificate",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="type",
             *         in="formData",
             *         description="Type of certificate to issue, such as certificate authority, client authentication, or server encryption",
             *         required=true,
             *         enum={"server", "user", "ca"},
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="subjects",
             *         in="formData",
             *         description="list of subjects for this certificate, first is CN, following are subject alternative names",
             *         required=true,
             *         type="array",
             *         @SWG\Items(
             *             type="string",
             *             description="subject cn or san ex: sub.domain.com",
             *         ),
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/CaCertificate")
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
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}",
             *     tags={"CA Certificates"},
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
             *             @SWG\Items(ref="#/definitions/CaCertificate")
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
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}",
             *     tags={"CA Certificates"},
             *     summary="Update certificate in an CA account",
             *     description="",
             *     operationId="UpdateCertificate",
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
             *         in="formData",
             *         description="name of new certificate",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="type",
             *         in="formData",
             *         description="Type of certificate to issue, such as certificate authority, client authentication, or server encryption",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="subjects",
             *         in="formData",
             *         description="list of subjects for this certificate, first is CN, following are subject alternative names",
             *         required=false,
             *         type="array",
             *         @SWG\Items(
             *             type="string",
             *             description="subject cn or san ex: sub.domain.com",
             *         ),
             *     ),
             *     @SWG\Response(
             *         response=200,
             *         description="successful operation",
             *         @SWG\Schema(
             *             type="array",
             *             @SWG\Items(ref="#/definitions/CaCertificate")
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
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}",
             *     tags={"CA Certificates"},
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
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}/generatekeys",
             *     tags={"CA Certificates"},
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
            $api->post('/{id}/generatekeys', $controller.'@certificateGenerateKeys');
            /**
             * @SWG\Post(
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}/generaterequest",
             *     tags={"CA Certificates"},
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
            $api->post('/{id}/generaterequest', $controller.'@certificateGenerateRequest');
            /**
             * @SWG\Post(
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}/sign",
             *     tags={"CA Certificates"},
             *     summary="Sign this certificates request",
             *     description="You must have signing permissions for the owning account AND a valid CSR for a ca to sign must be provided or generated",
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
            $api->post('/{id}/sign', $controller.'@certificateSign');
            /**
             * @SWG\Post(
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}/renew",
             *     tags={"CA Certificates"},
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
            $api->post('/{id}/renew', $controller.'@certificateRenew');
            /**
             * @SWG\Get(
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}/pkcs12",
             *     tags={"CA Certificates"},
             *     summary="Download certificate, chain, and private key PKCS12 format",
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
             *     path="/api/ca/accounts/{account_id}/certificates/{certificate_id}/pem",
             *     tags={"CA Certificates"},
             *     summary="Download certificate, chain, and private key PEM encoded",
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

    // test
    $options['middleware'] = ['api.throttle'];
    $api->group($options, function ($api) {
        // Certificate management routes under an account id
        $api->group(['prefix' => 'accounts/{account_id}/certificates', 'middleware' => 'api.throttle'], function ($api) {
            $controller = 'CaController';
            // TODO: Document this contraption
            $api->get('/{id}/pem/refresh', $controller.'@certificateRefreshPEM');
        });
    });

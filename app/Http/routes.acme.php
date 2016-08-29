<?php

    // This is all the ACME calls for acconuts, certs, etc.
    $api->group(['prefix' => 'acme', 'namespace' => 'App\Http\Controllers', 'middleware' => 'api.auth'], function ($api) {
        // Account management routes
        $api->group(['prefix' => 'accounts'], function ($api) {
            $controller = 'AcmeController';
            /**
             * @SWG\Get(
             *     path="/api/acme/accounts",
             *     tags={"Acme Accounts"},
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
             *     tags={"Acme Accounts"},
             *     summary="Create new ACME account",
             *     description="",
             *     operationId="createAcmeAccount",
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
             *         name="acmecaurl",
             *         in="formData",
             *         description="base url to ACME certificate authority",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="acmelicense",
             *         in="formData",
             *         description="url of ACME cert authority license agreement",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authtype",
             *         in="formData",
             *         description="authentication type for acme challenges",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authprovider",
             *         in="formData",
             *         description="provider for auth type",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authuser",
             *         in="formData",
             *         description="user for auth provider",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authpass",
             *         in="formData",
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
             *     tags={"Acme Accounts"},
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
             *     tags={"Acme Accounts"},
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
             *         name="acmecaurl",
             *         in="formData",
             *         description="base url to ACME certificate authority",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="acmelicense",
             *         in="formData",
             *         description="url of ACME cert authority license agreement",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authtype",
             *         in="formData",
             *         description="authentication type for acme challenges",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authprovider",
             *         in="formData",
             *         description="provider for auth type",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authuser",
             *         in="formData",
             *         description="user for auth provider",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="authpass",
             *         in="formData",
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
             *     tags={"Acme Accounts"},
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
             *     tags={"Acme Accounts"},
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
             *     tags={"Acme Accounts"},
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
             *     tags={"Acme Certificates"},
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
             *     tags={"Acme Certificates"},
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
             *         in="formData",
             *         description="name of new certificate",
             *         required=true,
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
             *             description="sibject cn or san ex: sub.domain.com",
             *         ),
             *     ),
             *     @SWG\Parameter(
             *         name="request",
             *         in="formData",
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
             *     tags={"Acme Certificates"},
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
             *     tags={"Acme Certificates"},
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
             *         in="formData",
             *         description="name of certificate",
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
             *     tags={"Acme Certificates"},
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
             *     tags={"Acme Certificates"},
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
             *     tags={"Acme Certificates"},
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
             *     tags={"Acme Certificates"},
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
             *     tags={"Acme Certificates"},
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
             *     tags={"Acme Certificates"},
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
             *         in="formData",
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
             *     tags={"Acme Certificates"},
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

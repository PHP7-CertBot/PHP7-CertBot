<?php

    // This is all the CA calls for accounts, certs, etc.
    $api->group(['prefix' => 'ca', 'namespace' => 'App\Http\Controllers', 'middleware' => 'api.auth'], function ($api) {
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
             *         name="zones",
             *         in="query",
             *         description="zones this ca is authorized to issue certificates for",
             *         required=true,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="query",
             *         description="ID number of coresponding certificate object, required for signing operations",
             *         required=false,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="crlurl",
             *         in="query",
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
             *         name="zones",
             *         in="query",
             *         description="zones this ca is authorized to issue certificates for",
             *         required=false,
             *         type="string"
             *     ),
             *     @SWG\Parameter(
             *         name="certificate_id",
             *         in="query",
             *         description="ID number of coresponding certificate object, required for signing operations",
             *         required=false,
             *         type="integer"
             *     ),
             *     @SWG\Parameter(
             *         name="crlurl",
             *         in="query",
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

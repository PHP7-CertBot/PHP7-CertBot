<?php

    // User authentication routes
    $api->group(['prefix' => 'authenticate', 'namespace' => 'App\Http\Controllers\Auth'], function ($api) {
        /**
         * @SWG\Get(
         *     path="/api/authenticate",
         *     tags={"Authentication"},
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
         *     tags={"Authentication"},
         *     summary="Get JSON web token by LDAP user authentication",
         *     @SWG\Parameter(
         *         name="username",
         *         in="formData",
         *         description="LDAP username",
         *         required=true,
         *         type="string"
         *     ),
         *     @SWG\Parameter(
         *         name="password",
         *         in="formData",
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

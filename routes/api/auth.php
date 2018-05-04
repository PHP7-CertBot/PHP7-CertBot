<?php

// User authentication routes
$options = [
               'prefix'     => 'authenticate',
               'namespace'  => 'Auth',
               'middleware' => [
                                   'api',
                                   'throttle:10,1',
                               ],
           ];
Route::group($options, function () {
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
    Route::post('', 'AuthController@authenticate');
});

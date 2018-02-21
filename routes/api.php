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

$api = app('Dingo\Api\Routing\Router');

$api->version('v1', function ($api) {
    /**
     * @SWG\Info(title="Certbot API", version="0.1")
     **/

    // Redirect requests to /api to the swagger documentation
    //$api->any('', function (Illuminate\Http\Request $request) {
    $api->any('', function () {
        return redirect('api/documentation/');
    });

    /**
     * @SWG\Get(
     *     path="/api/hello",
     *     summary="Hello world test for API troubleshooting",
     *     @SWG\Response(response="200", description="Hello world example")
     * )
     **/
    /*
    $api->any('hello', function (Illuminate\Http\Request $request) {
        return 'Hello '.$request->method().PHP_EOL;
    });
    */

    // user authentication routes
    require __DIR__.'/api.auth.php';

    // acme account and certificate routes
    require __DIR__.'/api.acme.php';

    // ca account and certificate routes
    require __DIR__.'/api.ca.php';
});

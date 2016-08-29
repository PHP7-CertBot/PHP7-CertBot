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

    // user authentication routes
    require(__DIR__.'/routes.auth.php');

    // acme account and certificate routes
    require(__DIR__.'/routes.acme.php');

    // ca account and certificate routes
    require(__DIR__.'/routes.ca.php');

});

<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

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
Route::middleware('api')->get('/hello', function (Request $request) {
    return 'hello world';
});

// This was the default file contents of this file, it has been disabled by PHP7-Laravel5-EnterpriseAuth
/*
Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
*/

// Redirect requests to /api to the swagger documentation
//$api->any('', function (Illuminate\Http\Request $request) {
Route::middleware('api')->get('', function (Request $request) {
    return redirect('api/documentation/');
});

// user authentication routes
require __DIR__.'/api/auth.php';

// acme account and certificate routes
require __DIR__.'/api/acme.php';

// ca account and certificate routes
require __DIR__.'/api/ca.php';

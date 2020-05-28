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
 * @SWG\Info(title="Certbot API", version="2.0")
 **/

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

// acme account and certificate routes
require __DIR__.'/api/acme.php';

// ca account and certificate routes
require __DIR__.'/api/ca.php';

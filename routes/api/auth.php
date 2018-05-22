<?php

// User authentication routes
$options = [
               'prefix'     => 'authenticate',
               'namespace'  => 'Auth',
               'middleware' => [
                                   'api',
                                   'throttle:20,1',
                               ],
           ];
Route::group($options, function () {
    Route::post('', 'AuthController@authenticate');
});

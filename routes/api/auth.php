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
    Route::post('', 'AuthController@authenticate');
});

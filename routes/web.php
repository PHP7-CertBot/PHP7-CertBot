<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('certbot');
});

Route::get('/monitor', function () {
    // Expired certs scanned/updated in the past 2 days
    $expired = \App\Monitor\Certificate::whereDate('expires_at', '<', \Carbon\Carbon::now())
                                       ->whereDate('updated_at', '>', \Carbon\Carbon::now()->subDays(2))
                                       ->orderBy('expires_at')
                                       ->get();
    // JSONify the SANs
    foreach ($expired as $key => $value) {
        $expired[$key]->subjects = json_encode($value->san);
    }

    // Valid certs expiring in the next month scanned/updated in the past 2 days
    $expiring = \App\Monitor\Certificate::whereDate('expires_at', '>', \Carbon\Carbon::now())
                                        ->whereDate('expires_at', '<', \Carbon\Carbon::now()->addMonth())
                                        ->whereDate('updated_at', '>', \Carbon\Carbon::now()->subDays(2))
                                        ->orderBy('expires_at')
                                        ->get();
    // JSONify the SANs
    foreach ($expiring as $key => $value) {
        $expiring[$key]->subjects = json_encode($value->san);
    }

    // build the views data
    $data = [
        'expired'  => $expired,
        'expiring' => $expiring,
    ];

    return view('monitor', $data);
})->middleware('auth');

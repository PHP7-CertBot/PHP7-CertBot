<?php

// This is all the monitoring for cert expiration soon / past
$middleware = [
    'api',
    'auth:api',
    'throttle:100,2',
];
Route::group(['prefix' => 'monitor', 'middleware' => $middleware], function () {
    /**
     * @SWG\Get(
     *     path="/api/monitor/expired",
     *     tags={"Expiration Monitoring"},
     *     summary="List places with expired certificates seen recently",
     *     description="",
     *     operationId="listAcmeAccounts",
     *     consumes={"application/json"},
     *     produces={"application/json"},
     *     @SWG\Response(
     *         response=200,
     *         description="successful operation"
     *     ),
     *     security={
     *         {"AzureAD": {}},
     *     }
     * )
     */
    Route::get('/expired', function () {
        // Expired certs scanned/updated in the past 2 days
        $expired = \App\Monitor\Certificate::whereDate('expires_at', '<', \Carbon\Carbon::now())
                                           ->whereDate('updated_at', '>', \Carbon\Carbon::now()->subDays(2))
                                           ->orderBy('expires_at')
                                           ->get();
        // JSONify the SANs
        foreach ($expired as $key => $value) {
            $expired[$key]->subjects = json_encode($value->san);
        }

        return $expired;
    });

    /**
     * @SWG\Get(
     *     path="/api/monitor/expiring",
     *     tags={"Expiration Monitoring"},
     *     summary="List places with expiring in the next month certificates seen recently",
     *     description="",
     *     operationId="listAcmeAccounts",
     *     consumes={"application/json"},
     *     produces={"application/json"},
     *     @SWG\Response(
     *         response=200,
     *         description="successful operation"
     *     ),
     *     security={
     *         {"AzureAD": {}},
     *     }
     * )
     */
    Route::get('/expiring', function () {
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

        return $expiring;
    });

});

<?php

namespace App;

use Illuminate\Support\Facades\Log;

class Utility
{
    public static function parsePemFromBody($body)
    {
        $pem = chunk_split(base64_encode($body), 64, "\n");

        return "-----BEGIN CERTIFICATE-----\n".$pem.'-----END CERTIFICATE-----';
    }

    public static function base64UrlSafeEncode($input)
    {
        //return base64_encode($input);
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    // TODO: turn this thing into a singleton maybe
    public static function log($message = '')
    {
        if ($message) {
            $messages[] = $message;
            file_put_contents(storage_path('logs/accountclient.log'),
                                \Metaclassing\Utility::dumperToString($message).PHP_EOL,
                                FILE_APPEND | LOCK_EX
                            );
            \Illuminate\Support\Facades\Log::info($message);
        }

        return $messages;
    }
}

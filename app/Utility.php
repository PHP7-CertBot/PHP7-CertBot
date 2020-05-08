<?php

namespace App;

use Illuminate\Support\Facades\Log;

class Utility
{
    public static function base64UrlSafeEncode($input)
    {
        //return base64_encode($input);
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    // TODO: turn this thing into a singleton maybe
    public static function log($message = '')
    {
        // because this is a static utility class, it doesnt have properties
        // and i dont want to re-design all of this junk, just cheat and go global
        global $messages;
        // initialize if unset or falsed
        if (! $messages) {
            $messages = [];
        }
        // if we have a new log message, append it
        if ($message) {
            $messages[] = $message;
            // stuff log messages in the acme account log file for funsies
            file_put_contents(storage_path('logs/accountclient.log'),
                                \Metaclassing\Utility::dumperToString($message).PHP_EOL,
                                FILE_APPEND | LOCK_EX
                            );
            // and dump it into the PSR-4 compliant logger
            \Illuminate\Support\Facades\Log::info($message);
        }

        return $messages;
    }
}

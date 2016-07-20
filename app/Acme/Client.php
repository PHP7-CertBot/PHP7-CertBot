<?php

/**
 * CertBot Acme Client & Certificate Authority Manager.
 *
 * PHP version 7
 *
 * This specific ACME client was adapted from analogic/lescript.
 *
 * @category  default
 * @author    Stanislav Humplik <sh@analogic.cz>
 * @author    metaclassing <metaclassing@SecureObscure.com>
 * @copyright 2015-2016 @authors
 * @license   http://www.freebsd.org/copyright/license.html  BSD License
 */
namespace App\Acme;

class Client
{
    private $lastCode;
    private $lastHeader;
    private $base;

    public function __construct($base)
    {
        $this->base = $base;
    }

    public function log($message)
    {
        $acmelogfile = storage_path('logs/acmeclient.log');
        // If we have a response, strip out all the nonprintable garbage from the log entry
        if (isset($message['response']) && $message['response']) {
            // Remove non-printable ascii characters EXCEPT \x0a which is new-line
            $message['response'] = preg_replace('/[\x00-\x09\x0b-\x1F\x80-\xFF]/', '', $message['response']);
        }
        file_put_contents($acmelogfile,
                            \metaclassing\Utility::dumperToString($message),
                            FILE_APPEND | LOCK_EX
                        );
    }

    private function curl($method, $url, $data = null)
    {
        $headers = ['Accept: application/json', 'Content-Type: application/json'];
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, preg_match('~^http~', $url) ? $url : $this->base.$url);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);

        // DO NOT DO THAT!
        // curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, false);
        // curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);

        switch ($method) {
            case 'GET':
                break;
            case 'POST':
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
                break;
        }

        $response = curl_exec($handle);

        $this->log(
                    [
                        'method'      => $method,
                        'url'         => $url,
                        'headers'     => $headers,
                        'data'        => $data,
                        'response'    => $response,
                    ]
                );

        if (curl_errno($handle)) {
            throw new \RuntimeException('Curl: '.curl_error($handle));
        }

        $header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);

        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        $this->lastHeader = $header;
        $this->lastCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);

        $data = json_decode($body, true);

        return $data === null ? $body : $data;
    }

    public function post($url, $data)
    {
        return $this->curl('POST', $url, $data);
    }

    public function get($url)
    {
        return $this->curl('GET', $url);
    }

    public function getLastNonce()
    {
        if (preg_match('~Replay\-Nonce: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }

        $this->curl('GET', '/directory');

        return $this->getLastNonce();
    }

    public function getLastLocation()
    {
        if (preg_match('~Location: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }
    }

    public function getLastCode()
    {
        return $this->lastCode;
    }

    public function getLastLinks()
    {
        preg_match_all('~Link: <(.+)>;rel="up"~', $this->lastHeader, $matches);

        return $matches[1];
    }
}

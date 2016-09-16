<?php

require_once __DIR__.'/vendor/autoload.php';

$url = 'https://certbot.mycompany.com/api';
$clientcert = '/crypto/automation@user.pem';
$deploy = [
            'adminer.mycompany.com'    => '/opt/adminer.mycompany.com/etc/certbot.pem',
            'api.mycompany.com'        => '/opt/api.mycompany.com/etc/certbot.pem',
            'bingo.mycompany.com'      => '/opt/bingo.mycompany.com/etc/certbot.pem',
            'crl.mycompany.com'        => '/opt/crl.mycompany.com/etc/certbot.pem',
            'xss.mycompany.com'        => '/opt/xss.mycompany.com/etc/certbot.pem',
            ''                         => '',
            ''                         => '',
            ''                         => '',
        ];

try {
    echo 'creating certbot client'.PHP_EOL;
    $certbot = new \Metaclassing\Curler\Certbot($url, $clientcert);

    foreach ($deploy as $name => $path) {
        if (! $name || ! $path) {
            continue;
        }
        echo 'deploying certificate name '.$name.' to '.$path.'...';
        $pem = $certbot->getCertificate($name);
        if (! $pem) {
            throw new \Exception('error retrieveing certificate named '.$name);
        }
        file_put_contents($path, $pem);
        echo ' done!'.PHP_EOL;
    }
} catch (\Exception $e) {
    echo 'Encountered exception: '.$e->getMessage().PHP_EOL;
}

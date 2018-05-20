<?php

/**
 * CertBot Acme Client & Certificate Authority Manager.
 *
 * PHP version 7
 *
 * Manage and distribute certificates using a Laravel 5.2 RESTful JSON API
 *
 * @category  default
 * @author    Metaclassing <Metaclassing@SecureObscure.com>
 * @copyright 2015-2016 @authors
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace Tests\Integration;

use App\User;
use Illuminate\Foundation\Testing\WithoutMiddleware;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;

class AcmeAccountTest extends IntegrationTestCase
{
    public function testAcmeAccountAPI()
    {
        $this->accountInfo = [
            'name'           => 'phpUnitAcmeAccount',
            'contact'        => 'phpUnit@example.com',
            'zones'          => env('TEST_ACME_ZONES'),
            'acmecaurl'      => env('TEST_ACME_CAURL'),
            'acmelicense'    => 'https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf',
            'authtype'       => env('TEST_ACME_AUTHTYPE'),
            'authprovider'   => env('TEST_ACME_AUTHPROVIDER'),
            'authaccount'    => env('TEST_ACME_AUTHACCOUNT'),
            'authuser'       => env('TEST_ACME_AUTHUSER'),
            'authpass'       => env('TEST_ACME_AUTHPASS'),
            ];
        $this->accountType = '\App\Acme\Account';
        $this->accountRoute = 'acme';
        $this->certificateType = '\App\Acme\Certificate';

        echo PHP_EOL.__METHOD__.' Starting Acme Account API tests';
        // Seed our test data, this entire test is wrapped in a transaction so will be auto-removed
        $this->seedUserAccounts();
        $this->setUser('Admin');
        $this->createAccount();
        $this->getAccounts();
        $this->createAcmeRegistration();
        $this->updateAccount();
        $this->updateAcmeRegistration();
        $this->seedBouncerUserRoles();
        // Set the authorized user in our web service
        $this->setUser('Manager');
        $this->getAccounts();
        $this->getAccountCertificates();
        // sync with ca tests
        // sync with ca tests
        // Try to make a new certificate signed by the acme authority
        echo PHP_EOL.__METHOD__.' Creating and signing new SERVER certificate with Acme authority';
        $this->createCertificate(env('TEST_ACME_ZONES'), [env('TEST_ACME_ZONES')], 'server');
        $this->getAccountCertificates(env('TEST_ACME_ZONES'));
        $this->updateCertificate(env('TEST_ACME_ZONES'), [env('TEST_ACME_ZONES'), 'phpunit.'.env('TEST_ACME_ZONES')]);
        $this->generateKeys(env('TEST_ACME_ZONES'));
        $this->generateCSR(env('TEST_ACME_ZONES'));
        $this->signCSR(env('TEST_ACME_ZONES'));
        // sync with ca tests
        // sync with ca tests
        // sync with ca tests
        // sync with ca tests
        // sync with ca tests
        // sync with ca tests
        // sync with ca tests
        // sync with ca tests
        // Use a DIFFERENT external library to validate the Acme authority certificate signatures
        $this->validateSignatures();
        $this->verifyKeyhashRefreshRoutes();
        // Run permissions testing
        $this->validateUserPermissions();
        // Run CLI command tests
        $this->runCommands();
        // Test our delete functions
        $this->setUser('Admin');
        $this->deleteCertificate(env('TEST_ACME_ZONES'));
        // sync with ca tests
        $this->deleteAccount();
        echo PHP_EOL.__METHOD__.' All verification complete, testing successful, database has been cleaned up';
    }

    protected function createAcmeRegistration()
    {
        echo PHP_EOL.__METHOD__.' Creating test Acme registration';
        $post = [];
        $account_id = $this->getAccountIdByName('phpUnitAcmeAccount');
        $response = $this->actingAs($this->user)->json('POST',
                        '/api/acme/accounts/'.$account_id.'/register',
                        $post);
        if (! isset($response->original['success'])) {
            dd($response);
        }
        $this->assertEquals(true, $response->original['success']);
    }

    protected function updateAcmeRegistration()
    {
        echo PHP_EOL.__METHOD__.' Updating test Acme registration';
        $put = [];
        $account_id = $this->getAccountIdByName('phpUnitAcmeAccount');
        $response = $this->actingAs($this->user)->json('PUT',
                        '/api/acme/accounts/'.$account_id.'/register',
                        $put);
        if (! isset($response->original['success'])) {
            dd($response);
        }
        $this->assertEquals(true, $response->original['success']);
    }

    protected function validateSignatures()
    {
        echo PHP_EOL.__METHOD__.' Validating Acme signed certificate signatures with openssl';
        $account_id = $this->getAccountIdByName('phpUnitAcmeAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $certificate = $this->certificateType::findOrFail($certificate_id);

        // I would really like to use an external tool like openssl to validate the signatures
        echo PHP_EOL.__METHOD__.' Validating CA and Cert signatures with OpenSSL';
        $fakeroot = '
-----BEGIN CERTIFICATE-----
MIIFATCCAumgAwIBAgIRAKc9ZKBASymy5TLOEp57N98wDQYJKoZIhvcNAQELBQAw
GjEYMBYGA1UEAwwPRmFrZSBMRSBSb290IFgxMB4XDTE2MDMyMzIyNTM0NloXDTM2
MDMyMzIyNTM0NlowGjEYMBYGA1UEAwwPRmFrZSBMRSBSb290IFgxMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA+pYHvQw5iU3v2b3iNuYNKYgsWD6KU7aJ
diddtZQxSWYzUI3U0I1UsRPTxnhTifs/M9NW4ZlV13ZfB7APwC8oqKOIiwo7IwlP
xg0VKgyz+kT8RJfYr66PPIYP0fpTeu42LpMJ+CKo9sbpgVNDZN2z/qiXrRNX/VtG
TkPV7a44fZ5bHHVruAxvDnylpQxJobtCBWlJSsbIRGFHMc2z88eUz9NmIOWUKGGj
EmP76x8OfRHpIpuxRSCjn0+i9+hR2siIOpcMOGd+40uVJxbRRP5ZXnUFa2fF5FWd
O0u0RPI8HON0ovhrwPJY+4eWKkQzyC611oLPYGQ4EbifRsTsCxUZqyUuStGyp8oa
aoSKfF6X0+KzGgwwnrjRTUpIl19A92KR0Noo6h622OX+4sZiO/JQdkuX5w/HupK0
A0M0WSMCvU6GOhjGotmh2VTEJwHHY4+TUk0iQYRtv1crONklyZoAQPD76hCrC8Cr
IbgsZLfTMC8TWUoMbyUDgvgYkHKMoPm0VGVVuwpRKJxv7+2wXO+pivrrUl2Q9fPe
Kk055nJLMV9yPUdig8othUKrRfSxli946AEV1eEOhxddfEwBE3Lt2xn0hhiIedbb
Ftf/5kEWFZkXyUmMJK8Ra76Kus2ABueUVEcZ48hrRr1Hf1N9n59VbTUaXgeiZA50
qXf2bymE6F8CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFMEmdKSKRKDm+iAo2FwjmkWIGHngMA0GCSqGSIb3DQEBCwUA
A4ICAQBCPw74M9X/Xx04K1VAES3ypgQYH5bf9FXVDrwhRFSVckria/7dMzoF5wln
uq9NGsjkkkDg17AohcQdr8alH4LvPdxpKr3BjpvEcmbqF8xH+MbbeUEnmbSfLI8H
sefuhXF9AF/9iYvpVNC8FmJ0OhiVv13VgMQw0CRKkbtjZBf8xaEhq/YqxWVsgOjm
dm5CAQ2X0aX7502x8wYRgMnZhA5goC1zVWBVAi8yhhmlhhoDUfg17cXkmaJC5pDd
oenZ9NVhW8eDb03MFCrWNvIh89DDeCGWuWfDltDq0n3owyL0IeSn7RfpSclpxVmV
/53jkYjwIgxIG7Gsv0LKMbsf6QdBcTjhvfZyMIpBRkTe3zuHd2feKzY9lEkbRvRQ
zbh4Ps5YBnG6CKJPTbe2hfi3nhnw/MyEmF3zb0hzvLWNrR9XW3ibb2oL3424XOwc
VjrTSCLzO9Rv6s5wi03qoWvKAQQAElqTYRHhynJ3w6wuvKYF5zcZF3MDnrVGLbh1
Q9ePRFBCiXOQ6wPLoUhrrbZ8LpFUFYDXHMtYM7P9sc9IAWoONXREJaO08zgFtMp4
8iyIYUyQAbsvx8oD2M8kRvrIRSrRJSl6L957b4AFiLIQ/GgV2curs0jje7Edx34c
idWw1VrejtwclobqNMVtG3EiPUIpJGpbMcJgbiLSmKkrvQtGng==
-----END CERTIFICATE-----
';
        file_put_contents('cacert', $fakeroot.PHP_EOL.$certificate->chain);
        file_put_contents('cert', $certificate->certificate);

        $output = shell_exec('openssl verify -verbose -CAfile cacert cert');
        echo ' '.trim($output);
        $this->assertEquals('cert: OK', trim($output));
        unlink('cacert');
        unlink('cert');
    }

    protected function runCommands()
    {
        // ./artisan acme:certificate
        $this->runCommandCertificate();
        // ./artisan acme:reauthorize
        $this->runCommandReauthorize();
        // ./artisan acme:renew
        $this->runCommandRenew();
        // ./artisan acme:monitor
        $this->runCommandMonitor();
    }

    protected function runCommandReauthorize()
    {
        // Get our test certificate
        $account_id = $this->getAccountIdByName($this->accountInfo['name']);
        // run acme:reauthorize eventhough i dont think it does anything...
        echo PHP_EOL.__METHOD__.' Validating command line operation ./artisan acme:reauthorize --account_id='.$account_id;
        \Artisan::call('acme:reauthorize', [
            '--account_id' => $account_id,
        ]);
        $resultAsText = \Artisan::output();
        echo PHP_EOL.__METHOD__.' Results:'.PHP_EOL.$resultAsText;
    }
}

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
use App\Acme\Account;
use App\Acme\Certificate;
use Illuminate\Foundation\Testing\WithoutMiddleware;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;

class AcmeAccountTest extends IntegrationTestCase
{
    public function testAcmeAccountAPI()
    {
        $this->accountName = 'phpUnitAcmeAccount';
        $this->accountType = '\App\Acme\Account';
        $this->accountRoute = 'acme';

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

        // Try to make a new certificate signed by the acme authority
        echo PHP_EOL.__METHOD__.' Creating and signing new certificate with Acme authority';
        $this->createCertificate();
        $this->getAccountCertificates();
        $this->updateCertificate();
        $this->generateKeys();
        $this->generateCSR();
        $this->signCSR();
        // Use a DIFFERENT external library to validate the Acme authority certificate signatures
        $this->validateSignatures();
        $this->verifyKeyhashRefreshRoutes();
        // Run permissions testing
        $this->validateUserPermissions();
        // Run CLI command tests
        $this->runCommands();
        // Test our delete functions
        $this->setUser('Admin');
        $this->deleteCertificate();
        $this->deleteAccount();
        echo PHP_EOL.__METHOD__.' All verification complete, testing successful, database has been cleaned up';
    }

    protected function createAccount()
    {
        echo PHP_EOL.__METHOD__.' Creating test Acme account';
        $post = [
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
        echo PHP_EOL.'acting as user '.$this->user->name.PHP_EOL;
        $response = $this->actingAs($this->user, 'api')->json('POST',
                        '/api/acme/accounts',
                        $post);
//        $response = $this->actingAs($this->user, 'api')->call('POST',
//                        '/api/acme/accounts',
//                        $post);
        if (! isset($response->original['success'])) {
            dd($response);
        }
        $this->assertEquals(true, $response->original['success']);
    }

    protected function createAcmeRegistration()
    {
        echo PHP_EOL.__METHOD__.' Creating test Acme registration';
        $post = [];
        $account_id = $this->getAccountIdByName('phpUnitAcmeAccount');
        $response = $this->actingAs($this->user)->call('POST',
                        '/api/acme/accounts/'.$account_id.'/register',
                        $post);
        if (! isset($response->original['success'])) {
            dd($response);
        }
        $this->assertEquals(true, $response->original['success']);
    }

    protected function updateAccount()
    {
        echo PHP_EOL.__METHOD__.' Updating test Acme account';
        $put = [
               'contact'        => 'phpUnit@'.env('TEST_ACME_ZONES'),
               ];
        $account_id = $this->getAccountIdByName('phpUnitAcmeAccount');
        $response = $this->actingAs($this->user)->call('PUT',
                        '/api/acme/accounts/'.$account_id,
                        $put);
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
        $response = $this->actingAs($this->user)->call('PUT',
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
        $certificate = Certificate::findOrFail($certificate_id);

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

    protected function validateUserPermissions()
    {
        echo PHP_EOL.__METHOD__.' Validating user roles have proper access';
        /*
                /accounts/
        1            $api->get('', $controller.'@listAccounts');
         2           $api->get('/{id}', $controller.'@getAccount');
          3          $api->post('', $controller.'@createAccount');
           4         $api->put('/{id}', $controller.'@updateAccount');
            5        $api->delete('/{id}', $controller.'@deleteAccount'); /**/
        $this->setUser('Manager');
        $this->validateAccountRouteAccess([
                                           1, 1, 0, 1, 0,
                                           ]);
        /*      /accounts/{account_id}/certificates
        1            $api->get('', $controller.'@listCertificates');
         2           $api->get('/{id}', $controller.'@getCertificate');
          3          $api->post('', $controller.'@createCertificate');
           4         $api->get('/{id}/generaterequest', $controller.'@certificateGenerateRequest');
        1            $api->get('/{id}/sign', $controller.'@certificateSign');
         2           $api->get('/{id}/pkcs12', $controller.'@certificateDownloadPKCS12');
          3          $api->get('/{id}/pem', $controller.'@certificateDownloadPEM'); /**/
        $this->validateCertificateRouteAccess([
                                               1, 1, 1, 1,
                                               1, 1, 1, 1,
                                               ]);
        //
        $this->setUser('Signer');
        $this->validateAccountRouteAccess([
                                           1, 1, 0, 0, 0,
                                           ]);
        $this->validateCertificateRouteAccess([
                                               1, 1, 1, 1,
                                               1, 1, 1, 1,
                                               ]);
        //
        $this->setUser('Operator');
        $this->validateAccountRouteAccess([
                                           1, 1, 0, 0, 0,
                                           ]);
        $this->validateCertificateRouteAccess([
                                               1, 1, 1, 1,
                                               0, 0, 1, 1,
                                               ]);
        //
        $this->setUser('Unauthorized');
        $this->validateAccountRouteAccess([
                                           0, 0, 0, 0, 0,
                                           ]);
        $this->validateCertificateRouteAccess([
                                               0, 0, 0, 0,
                                               0, 0, 0, 0,
                                               ]);
    }

    protected function validateAccountRouteAccess($expected)
    {
        echo PHP_EOL.__METHOD__.' Validating account route access conditions';
        $i = 0;
        $account_id = $this->getAccountIdByName('phpUnitAcmeAccount');

        echo PHP_EOL.__METHOD__.' User can list accounts: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/acme/accounts');
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(0, count($response->original['accounts']));
        }

        echo PHP_EOL.__METHOD__.' User can view assigned account: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/acme/accounts/'.$account_id);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can create new account: '.$expected[$i];
        $post = [
                'name'           => 'phpUnitAcmeAccount',
                'contact'        => 'phpUnit@example.com',
                'zones'          => env('TEST_ACME_ZONES'),
                'acmecaurl'      => env('TEST_ACME_CAURL'),
                'acmelicense'    => 'https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf',
                'authtype'       => env('TEST_ACME_AUTHTYPE'),
                'authprovider'   => env('TEST_ACME_AUTHPROVIDER'),
                'authuser'       => env('TEST_ACME_AUTHUSER'),
                'authpass'       => env('TEST_ACME_AUTHPASS'),
                ];
        $response = $this->actingAs($this->user)->call('POST',
                        '/api/acme/accounts',
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can edit assigned account: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('PUT',
                        '/api/acme/accounts/'.$account_id,
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can delete assigned account: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('DELETE',
                        '/api/acme/accounts/'.$account_id,
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
    }

    protected function validateCertificateRouteAccess($expected)
    {
        echo PHP_EOL.__METHOD__.' Validating certificate route access conditions';
        $i = 0;
        $account_id = $this->getAccountIdByName('phpUnitAcmeAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        //
        echo PHP_EOL.__METHOD__.' User can certificates: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/acme/accounts/'.$account_id.'/certificates');
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(0, count($response->original['certificates']));
        }
        //
        echo PHP_EOL.__METHOD__.' User can view assigned certificate: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/acme/accounts/'.$account_id.'/certificates/'.$certificate_id);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can create new certificate: '.$expected[$i];
        $post = [
                'name'             => 'phpUnit Test Cert',
                'subjects'         => [env('TEST_ACME_ZONES')],
                'type'             => 'server',
                ];
        $response = $this->actingAs($this->user)->call('POST',
                        '/api/acme/accounts/'.$account_id.'/certificates',
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can generate csr: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('POST', '/api/acme/accounts/'.$account_id.'/certificates/'.$certificate_id.'/generaterequest');
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' SKIPPING USER SIGN TEST due to ACME validation frequency: '.$expected[$i++];
        //

        //
        echo PHP_EOL.__METHOD__.' User can view pkcs12: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/acme/accounts/'.$account_id.'/certificates/'.$certificate_id.'/pkcs12');
        if ($expected[$i++]) {
            // I have literally no idea how to test this response format
        } else {
            //$this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can view pem: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/acme/accounts/'.$account_id.'/certificates/'.$certificate_id.'/pem');
        if ($expected[$i++]) {
            // I have literally no idea how to test this response format
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
    }

    protected function runCommands()
    {
        // acme:certificate
        $account_id = $this->getAccountIdByName('phpUnitAcmeAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $certificate = Certificate::findOrFail($certificate_id);
        $pem = $certificate->privatekey.PHP_EOL
             .$certificate->certificate.PHP_EOL
             .$certificate->chain.PHP_EOL;
        echo PHP_EOL.__METHOD__.' Validating command line operation ./artisan acme:certificate --certificate_id='.$certificate_id.PHP_EOL;
        Artisan::call('acme:certificate', [
            'certificate_id' => $certificate_id,
        ]);
        // I have really not found a good way to get the output of these commands for comparison

        // acme:reauthorize
        echo PHP_EOL.__METHOD__.' Validating command line operation ./artisan acme:reauthorize --account_id='.$account_id;
        Artisan::call('acme:reauthorize', [
            '--account_id' => $account_id,
        ]);

        // acme:renew
        echo PHP_EOL.__METHOD__.' Validating command line operation ./artisan acme:renew --account_id='.$account_id;
        Artisan::call('acme:renew', [
            '--account_id' => $account_id,
        ]);
    }
}

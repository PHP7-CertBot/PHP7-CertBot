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
use Tests\TestCase;
use Illuminate\Foundation\Testing\WithoutMiddleware;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;

class IntegrationTestCase extends TestCase
{
    use DatabaseTransactions;

    protected $user;
    protected $accounts;
    protected $accountcertificates;
    protected $accountType;
    protected $accountRoute;
    protected $accountName;

    protected function grantRolesPermissionsToThings($roles, $permissions, $things)
    {
        // Make sure all our variables are in fact arrays so that we can iterate through them
        if (! is_array($roles)) {
            $roles = [$roles];
        }
        if (! is_array($permissions)) {
            $permissions = [$permissions];
        }
        if (! is_array($things)) {
            $things = [$things];
        }
        // Roles is an array of role names (strings)
        foreach ($roles as $role) {
            // Permissions is an array of permission names (strings)
            foreach ($permissions as $permission) {
                // Things is an array of specific object instances or class types ($thing or Thing::class
                foreach ($things as $thing) {
                    \Bouncer::allow($role)->to($permission, $thing);
                }
            }
        }
    }

    protected function seedUserAccounts()
    {
        echo PHP_EOL.__METHOD__.' Creating test user accounts';
        // Types of accounts to make and test
        $types = [
                 'Admin',
                 'Manager',
                 'Signer',
                 'Operator',
                 'Unauthorized',
                 ];
        // Make each type of account in a standard format
        foreach ($types as $id => $type) {
            $userdata = [
                            'name'              => 'phpUnit-'.$type,
                            'email'             => $type.'@phpUnit',
                            //'password'          => bcrypt(''),
                            'azure_id'          => 'phpUnit-'.$type,
                            'userPrincipalName' => $type.'@phpUnit',
                            ];
            // TODO: make a more interoperable way to do this... I dont like making UPN and azure id fillable
            $newuser = User::create($userdata);
        }
        // Create roles for the admin
        $roles = ['phpunit-admin'];
        $permissions = ['create', 'delete', 'update', 'sign', 'read'];
        $things = [$this->accountType];
        $this->grantRolesPermissionsToThings($roles, $permissions, $things);
        // Grant the admin user we just created in bouncer so we can call account creation
        $user = User::where('name', 'phpUnit-Admin')->first();
        \Bouncer::assign('phpunit-admin')->to($user);
    }

    protected function seedBouncerUserRoles()
    {
        echo PHP_EOL.__METHOD__.' Seeding user roles with different access levels';
        // Roles for CA account testing
        $account = $this->accountType::where('name', $this->accountName)->first();
        $roles = ['phpunit-manager'];
        $permissions = ['create', 'update', 'sign', 'read'];
        $this->grantRolesPermissionsToThings($roles, $permissions, [$account]);

        $roles = ['phpunit-signer'];
        $permissions = ['sign', 'read'];
        $this->grantRolesPermissionsToThings($roles, $permissions, [$account]);

        $roles = ['phpunit-operator'];
        $permissions = ['read'];
        $this->grantRolesPermissionsToThings($roles, $permissions, [$account]);

        // Map phpunit users to their roles
        $user = User::where('name', 'phpUnit-Manager')->first();
        \Bouncer::assign('phpunit-manager')->to($user);
        $user = User::where('name', 'phpUnit-Signer')->first();
        \Bouncer::assign('phpunit-signer')->to($user);
        $user = User::where('name', 'phpUnit-Operator')->first();
        \Bouncer::assign('phpunit-operator')->to($user);
    }

    protected function setUser($role)
    {
        echo PHP_EOL.__METHOD__.' Setting user to role '.$role;
        $this->user = User::where('name', 'phpUnit-'.$role)->first();
    }

    protected function getAccounts()
    {
        echo PHP_EOL.__METHOD__.' Loading latest accounts visible to current role';
        $response = $this->actingAs($this->user)->call('GET', '/api/'.$this->accountRoute.'/accounts');
        $this->accounts = $response->original['accounts'];
        $this->assertEquals(true, $response->original['success']);
        echo ' - found '.count($response->original['accounts']).' accounts';
    }

    protected function getAccountCertificates()
    {
        echo PHP_EOL.__METHOD__.' Loading certificates for accounts';
        $this->accountcertificates = [];
        foreach ($this->accounts as $account) {
            $response = $this->actingAs($this->user)->call('GET',
                                    '/api/'.$this->accountRoute.'/accounts/'.$account['id'].'/certificates');
            $this->assertEquals(true, $response->original['success']);
            $this->accountcertificates[$account['id']] = $response->original['certificates'];
            echo ' - found '.count($response->original['certificates']).' in account '.$account['id'];
        }
    }

    protected function getAccountIdByName($name)
    {
        foreach ($this->accounts as $account) {
            if ($account['name'] == $name) {
                return $account['id'];
            }
        }
        throw new \Exception('could not identify account id for account named '.$name);
    }

    protected function getAccountCertificateIdByName($account_id, $name)
    {
        foreach ($this->accountcertificates[$account_id] as $certificate) {
            if ($certificate['name'] == $name) {
                return $certificate['id'];
            }
        }
        dd($this->accountcertificates);
        throw new \Exception('could not identify certificate id for account id '.$account_id.' named '.$name);
    }

    protected function createCertificate()
    {
        echo PHP_EOL.__METHOD__.' Creating new certificate for test zone';
        $account_id = $this->getAccountIdByName($this->accountName);
        $post = [
                    'name'     => env('TEST_ACME_ZONES'),
                    'subjects' => [env('TEST_ACME_ZONES')],
                    'type'     => 'server',
                ];
        $response = $this->actingAs($this->user)->call('POST',
                                '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates',
                                $post);
        $this->assertEquals(true, $response->original['success']);
    }

    protected function updateCertificate()
    {
        echo PHP_EOL.__METHOD__.' Updating certificate for test zone';
        $account_id = $this->getAccountIdByName($this->accountName);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $put = [
                    'subjects' => ['phpunit.'.env('TEST_ACME_ZONES')],
               ];
        $response = $this->actingAs($this->user)->call('PUT',
                                '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id,
                                $put);
        $this->assertEquals(true, $response->original['success']);
    }

    protected function generateKeys()
    {
        echo PHP_EOL.__METHOD__.' Generating keys for example cert';
        $account_id = $this->getAccountIdByName($this->accountName);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $response = $this->actingAs($this->user)->call('POST',
                                '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id.'/generatekeys');
        $this->assertEquals(true, $response->original['success']);
    }

    protected function generateCSR()
    {
        echo PHP_EOL.__METHOD__.' Generating csr for example cert';
        $account_id = $this->getAccountIdByName($this->accountName);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $response = $this->actingAs($this->user)->call('POST',
                                '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id.'/generaterequest');
        $this->assertEquals(true, $response->original['success']);
    }

    protected function signCSR()
    {
        echo PHP_EOL.__METHOD__.' Signing csr for example cert';
        $account_id = $this->getAccountIdByName($this->accountName);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $response = $this->actingAs($this->user)->call('POST',
                                '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id.'/sign');
        if (! $response->original['success']) {
            \Metaclassing\Utility::dumper($response);
        }
        $this->assertEquals(true, $response->original['success']);
    }

    protected function validateSignatures()
    {
        echo PHP_EOL.__METHOD__.' Validating Acme signed certificate signatures with openssl';
        $account_id = $this->getAccountIdByName($this->accountName);
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
        $account_id = $this->getAccountIdByName($this->accountName);

        echo PHP_EOL.__METHOD__.' User can list accounts: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/'.$this->accountRoute.'/accounts');
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(0, count($response->original['accounts']));
        }

        echo PHP_EOL.__METHOD__.' User can view assigned account: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/'.$this->accountRoute.'/accounts/'.$account_id);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can create new account: '.$expected[$i];
        $post = [
                'name'           => $this->accountName,
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
                        '/api/'.$this->accountRoute.'/accounts',
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can edit assigned account: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('PUT',
                        '/api/'.$this->accountRoute.'/accounts/'.$account_id,
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can delete assigned account: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('DELETE',
                        '/api/'.$this->accountRoute.'/accounts/'.$account_id,
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
        $account_id = $this->getAccountIdByName($this->accountName);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        //
        echo PHP_EOL.__METHOD__.' User can certificates: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates');
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(0, count($response->original['certificates']));
        }
        //
        echo PHP_EOL.__METHOD__.' User can view assigned certificate: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id);
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
                        '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates',
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can generate csr: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('POST', '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id.'/generaterequest');
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' SKIPPING USER SIGN TEST due to frequency: '.$expected[$i++];
        //

        //
        echo PHP_EOL.__METHOD__.' User can view pkcs12: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id.'/pkcs12');
        if ($expected[$i++]) {
            // I have literally no idea how to test this response format
        } else {
            //$this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can view pem: '.$expected[$i];
        $response = $this->actingAs($this->user)->call('GET', '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id.'/pem');
        if ($expected[$i++]) {
            // I have literally no idea how to test this response format
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
    }

    protected function verifyKeyhashRefreshRoutes()
    {
        $account_id = $this->getAccountIdByName($this->accountName);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $certificate = Certificate::findOrFail($certificate_id);
        $keyhash = $certificate->getPrivateKeyHash();
        $response = $this->actingAs($this->user)->call('GET', '/api/'.$this->accountRoute.'/accounts');

        echo PHP_EOL.__METHOD__.' Keyhash can refresh pem';
        $response = $this->call('GET', '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id.'/pem/refresh?keyhash='.$keyhash);
        if ($response->getStatusCode() != 200) {
            dd($response);
        }
        $this->assertEquals(200, $response->getStatusCode());

        echo PHP_EOL.__METHOD__.' Keyhash can refresh pkcs12';
        $response = $this->call('GET', '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id.'/pkcs12/refresh?keyhash='.$keyhash);
        if ($response->getStatusCode() != 200) {
            dd($response);
        }
        $this->assertEquals(200, $response->getStatusCode());
    }

    protected function deleteCertificate()
    {
        echo PHP_EOL.__METHOD__.' Deleting certificate for test zone';
        $account_id = $this->getAccountIdByName($this->accountName);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $response = $this->actingAs($this->user)->call('DELETE',
                                '/api/'.$this->accountRoute.'/accounts/'.$account_id.'/certificates/'.$certificate_id);
        if ($response->getStatusCode() != 200) {
            dd($response);
        }
        $this->assertEquals(200, $response->getStatusCode());
    }

    protected function deleteAccount()
    {
        echo PHP_EOL.__METHOD__.' Deleting test '.$this->accountType.' account';
        $account_id = $this->getAccountIdByName($this->accountName);
        $response = $this->actingAs($this->user)->call('DELETE',
                        '/api/'.$this->accountRoute.'/accounts/'.$account_id);
        if ($response->getStatusCode() != 200) {
            dd($response);
        }
        $this->assertEquals(200, $response->getStatusCode());
    }
}

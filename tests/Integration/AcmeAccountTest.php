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
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Foundation\Testing\WithoutMiddleware;

class AcmeAccountTest extends IntegrationTestCase
{
    public function testAcmeAccountAPI()
    {
        $this->assertEquals(true, true);

        $this->accountInfo = [
            'name'           => 'phpUnitAcmeAccount',
            'contact'        => 'phpUnit@'.env('TEST_ACME_ZONES'),
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
        //$this->updateAccount();
        //$this->updateAcmeRegistration();
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
        // Run CLI command tests
        $this->runCommands();
        // Run permissions testing
        $this->validateUserPermissions();
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
MIIFmDCCA4CgAwIBAgIQU9C87nMpOIFKYpfvOHFHFDANBgkqhkiG9w0BAQsFADBm
MQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy
aXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ
ZWFyIFgxMB4XDTE1MDYwNDExMDQzOFoXDTM1MDYwNDExMDQzOFowZjELMAkGA1UE
BhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl
YXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRlbmQgUGVhciBYMTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdDTa1QgGBWSYkyMhsc
ZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPWnL++fgehT0FbRHZg
jOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigkkmx8OiCO68a4QXg4
wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZGTIf/oRt2/c+dYmD
oaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6VP19sTGy3yfqK5tPt
TdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkLYC0Ft2cYUyHtkstO
fRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2UPQFxmWFRQnFjaq6
rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/2dBZKmJqxHkxCuOQ
FjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRMEeOXUYvbV4lqfCf8
mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEmQWUOTWIoDQ5FOia/
GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eVEGOIpn26bW5LKeru
mJxa/CFBaKi4bRvmdJRLAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB
Af8EBTADAQH/MB0GA1UdDgQWBBS182Xy/rAKkh/7PH3zRKCsYyXDFDANBgkqhkiG
9w0BAQsFAAOCAgEAncDZNytDbrrVe68UT6py1lfF2h6Tm2p8ro42i87WWyP2LK8Y
nLHC0hvNfWeWmjZQYBQfGC5c7aQRezak+tHLdmrNKHkn5kn+9E9LCjCaEsyIIn2j
qdHlAkepu/C3KnNtVx5tW07e5bvIjJScwkCDbP3akWQixPpRFAsnP+ULx7k0aO1x
qAeaAhQ2rgo1F58hcflgqKTXnpPM02intVfiVVkX5GXpJjK5EoQtLceyGOrkxlM/
sTPq4UrnypmsqSagWV3HcUlYtDinc+nukFk6eR4XkzXBbwKajl0YjztfrCIHOn5Q
CJL6TERVDbM/aAPly8kJ1sWGLuvvWYzMYgLzDul//rUF10gEMWaXVZV51KpS9DY/
5CunuvCXmEQJHo7kGcViT7sETn6Jz9KOhvYcXkJ7po6d93A/jy4GKPIPnsKKNEmR
xUuXY4xRdh45tMJnLTUDdC9FIU0flTeO9/vNpVA8OPU1i14vCz+MU8KX1bV3GXm/
fxlB7VBBjX9v5oUep0o/j68R/iDlCOM4VVfRa8gX6T2FU7fNdatvGro7uQzIvWof
gN9WUwCbEMBy/YhBSrXycKA8crgGg3x1mIsopn88JKwmMBa68oS7EHM9w7C4y71M
7DiA+/9Qdp9RBWJpTS9i/mDnJg1xvo8Xz49mrrgfmcAXTCJqXi24NatI3Oc=
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

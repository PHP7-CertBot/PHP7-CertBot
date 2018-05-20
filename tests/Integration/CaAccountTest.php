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

class CaAccountTest extends IntegrationTestCase
{
    public function testCaAccountAPI()
    {
        $this->accountInfo = [
            'name'           => 'phpUnitCaAccount',
            'contact'        => 'phpUnit@example.com',
            'zones'          => env('TEST_ACME_ZONES'),
            'crlurl'         => 'http://crl.example.com/phpunit',
            // sync with acme tests
            // sync with acme tests
            // sync with acme tests
            // sync with acme tests
            // sync with acme tests
            // sync with acme tests
            ];
        $this->accountType = '\App\Ca\Account';
        $this->accountRoute = 'ca';
        $this->certificateType = '\App\Ca\Certificate';

        echo PHP_EOL.__METHOD__.' Starting CA Account API tests';
        // Seed our test data, this entire test is wrapped in a transaction so will be auto-removed
        $this->seedUserAccounts();
        $this->setUser('Admin');
        $this->createAccount();
        $this->getAccounts();
        // sync with acme tests
        $this->updateAccount();
        // sync with acme tests
        $this->seedBouncerUserRoles();
        // Set the authorized user in our web service
        $this->setUser('Manager');
        $this->getAccounts();
        $this->getAccountCertificates();
        // Self sign our CA account so we can use it
        $this->selfSignCaAccountCertificates();
        // Try to make a new certificate signed by our CA
        echo PHP_EOL.__METHOD__.' Creating and signing new SERVER certificate with our CA';
        $this->createCertificate(env('TEST_ACME_ZONES'), [env('TEST_ACME_ZONES')], 'server');
        $this->getAccountCertificates(env('TEST_ACME_ZONES'));
        $this->updateCertificate(env('TEST_ACME_ZONES'), [env('TEST_ACME_ZONES'), 'phpunit.'.env('TEST_ACME_ZONES')]);
        $this->generateKeys(env('TEST_ACME_ZONES'));
        $this->generateCSR(env('TEST_ACME_ZONES'));
        $this->signCSR(env('TEST_ACME_ZONES'));
        // Do the same testing for a USER certificate
        echo PHP_EOL.__METHOD__.' Creating and signing new USER certificate with our CA';
        $this->createCertificate('robert.builder', ['robert.builder'], 'user');
        $this->getAccountCertificates();
        $this->updateCertificate('robert.builder', ['robert.builder', 'robert.builder@test.domain']);
        $this->generateKeys('robert.builder');
        $this->generateCSR('robert.builder');
        $this->signCSR('robert.builder');
        // Use a DIFFERENT external library to validate the CA and certificate signatures
        $this->validateSignatures();
        $this->verifyKeyhashRefreshRoutes();
        // Run permissions testing
        $this->validateUserPermissions();
        // Run CLI command tests
        $this->runCommands();
        // Test our delete functions
        $this->setUser('Admin');
        $this->deleteCertificate(env('TEST_ACME_ZONES'));
        $this->deleteCertificate('robert.builder');
        $this->deleteAccount();
        echo PHP_EOL.__METHOD__.' All verification complete, testing successful, database has been cleaned up';
    }

    protected function createAccount()
    {
        $response = parent::createAccount();
        $accountId = $response->original['account']['id'];
        $account = $this->accountType::findOrFail($accountId);
        echo PHP_EOL.__METHOD__.' Creating test CA certificate';
        $post = [
                'name'             => 'phpUnit Root CA',
                'subjects'         => '[]',
                'type'             => 'ca',
                ];
        $response = $this->actingAs($this->user)
                         ->json('POST',
                                '/api/ca/accounts/'.$account->id.'/certificates/',
                                $post);
        if (! isset($response->original['success'])) {
            dd($response);
        }
        $this->assertEquals(true, $response->original['success']);
        $certificateId = $response->original['certificate']['id'];
        $certificate = $this->certificateType::findOrFail($certificateId);
        $account->certificate_id = $certificate->id;
        $account->save();
        echo PHP_EOL.__METHOD__.' Generating test CA keys';
        $response = $this->actingAs($this->user, 'api')
                         ->json('POST', '/api/ca/accounts/'.$account->id.'/certificates/'.$certificate->id.'/generatekeys');
        $this->assertEquals(true, $response->original['success']);
    }

    protected function selfSignCaAccountCertificates()
    {
        echo PHP_EOL.__METHOD__.' Self signing phpUnit Root CA cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'phpUnit Root CA');
        $response = $this->actingAs($this->user, 'api')
                         ->json('POST', '/api/ca/accounts/'.$account_id.'/certificates/'.$certificate_id.'/sign');
        $this->assertEquals(true, $response->original['success']);
    }

    protected function validateSignatures()
    {
        echo PHP_EOL.__METHOD__.' Validating CA and certificate signatures with openssl';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'phpUnit Root CA');
        $cacertificate = $this->certificateType::findOrFail($certificate_id);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, env('TEST_ACME_ZONES'));
        $certificate = $this->certificateType::findOrFail($certificate_id);
        $this->assertEquals($cacertificate->certificate, $certificate->chain);
        // I would really like to use an external tool like openssl to validate the signatures
        echo PHP_EOL.__METHOD__.' Validating CA and Cert signatures with OpenSSL';

        file_put_contents('cacert', $cacertificate->certificate);
        file_put_contents('cert', $certificate->certificate);
        $output = shell_exec('openssl verify -verbose -CAfile cacert cacert');
        $this->assertEquals('cacert: OK', trim($output));
        $output = shell_exec('openssl verify -verbose -CAfile cacert cert');
        echo ' '.trim($output);
        $this->assertEquals('cert: OK', trim($output));
        unlink('cacert');
        unlink('cert');
    }

    protected function runCommands()
    {
        // ./artisan ca:certificate
        $this->runCommandCertificate();

        // ./artisan ca:renew
        $this->runCommandRenew();
        // ./artisan ca:monitor
        $this->runCommandMonitor();
    }
}

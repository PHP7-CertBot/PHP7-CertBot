<?php

/**
 * CertBot Acme Client & Certificate Authority Manager.
 *
 * PHP version 7
 *
 * Manage and distribute certificates using a Laravel 5.2 RESTful JSON API
 *
 * @category  default
 * @author    metaclassing <metaclassing@SecureObscure.com>
 * @copyright 2015-2016 @authors
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */
use Illuminate\Foundation\Testing\WithoutMiddleware;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\User;
use App\Ca\Account;
use App\Ca\Certificate;

class CaAccountTest extends TestCase
{
    use DatabaseTransactions;

    protected $token;
    protected $accounts;
    protected $accountcertificates;

    public function testCaAccountAPI()
    {
        echo PHP_EOL.__METHOD__.' Starting CA Account API tests';
        // Seed our test data, this entire test is wrapped in a transaction so will be auto-removed
        $this->seedUserAccounts();
        $this->getJWT('Admin');
        $this->seedCaAccounts();
        $this->seedBouncerUserRoles();
        // Get a JWT for the authorized user in our web service
        $this->getJWT('Manager');
        $this->getAccounts();
        $this->getAccountCertificates();
        // Self sign our CA account so we can use it
        echo PHP_EOL.__METHOD__.' Setting up our test CA';
        $this->selfSignCaAccountCertificates();
        // Try to make a new certificate signed by our CA
        echo PHP_EOL.__METHOD__.' Creating and signing new certificate with our CA';
        $this->createCertificate();
        $this->getAccountCertificates();
        $this->generateCSR();
        $this->signCSR();
        // Use a DIFFERENT external library to validate the CA and certificate signatures
        $this->validateSignatures();
        // Run permissions testing
        $this->validateUserPermissions();
        echo PHP_EOL.__METHOD__.' All verification complete, testing successful, database has been cleaned up';
    }

    protected function seedUserAccounts()
    {
        echo PHP_EOL.__METHOD__.' Creating test user accounts';
        $types = [
                 'Admin',
                 'Manager',
                 'Signer',
                 'Operator',
                 'Unauthorized',
                 ];
        foreach ($types as $id => $type) {
            User::create([
                          'username' => 'phpUnit-'.$type,
                          'dn'       => 'CN=phpUnit-'.$type,
                          'password' => bcrypt(''),
                          ]);
        }

        // Grant the admin user we just created in bouncer so we can call account creation
        $user = User::where('username', 'phpUnit-Admin')->first();
        Bouncer::assign('admin')->to($user);
    }

    protected function seedCaAccounts()
    {
        echo PHP_EOL.__METHOD__.' Creating test CA account';
        $post = [
                'name'           => 'phpUnitCaAccount',
                'contact'        => 'phpUnit@example.com',
                'zones'          => 'example.com',
                'crlurl'         => 'http://crl.example.com/phpunit',
                ];
        $response = $this->call('POST',
                        '/api/ca/account/?token='.$this->token,
                        $post);
        $this->assertEquals(true, $response->original['success']);
        $account = Account::find($response->original['account']['id']);

        echo PHP_EOL.__METHOD__.' Creating test CA certificate';
        $post = [
                'name'             => 'phpUnit Root CA',
                'subjects'         => '[]',
                'type'             => 'ca',
                ];
        $response = $this->call('POST',
                        '/api/ca/account/'.$account->id.'/certificate/?token='.$this->token,
                        $post);
        $this->assertEquals(true, $response->original['success']);
        $certificate = Certificate::find($response->original['certificate']['id']);
        $account->certificate_id = $certificate->id;
        $account->save();
    }

    protected function seedBouncerUserRoles()
    {
        echo PHP_EOL.__METHOD__.' Seeding user roles with different access levels';
        // Roles for CA account testing
        $ca_account = Account::where('name', 'phpUnitCaAccount')->first();
        Bouncer::allow('phpunit-manager')->to('manage', $ca_account);
        Bouncer::allow('phpunit-signer')->to('sign', $ca_account);
        Bouncer::allow('phpunit-operator')->to('operate', $ca_account);

        // Map phpunit users to their roles
        $user = User::where('username', 'phpUnit-Manager')->first();
        Bouncer::assign('phpunit-manager')->to($user);
        $user = User::where('username', 'phpUnit-Signer')->first();
        Bouncer::assign('phpunit-signer')->to($user);
        $user = User::where('username', 'phpUnit-Operator')->first();
        Bouncer::assign('phpunit-operator')->to($user);
    }

    protected function getJWT($role)
    {
        echo PHP_EOL.__METHOD__.' Generating JWT for role '.$role;
        $credentials = ['dn' => 'CN=phpUnit-'.$role, 'password' => ''];
        $this->token = JWTAuth::attempt($credentials);
    }

    protected function getAccounts()
    {
        echo PHP_EOL.__METHOD__.' Loading latest accounts visible to current role';
        $response = $this->call('GET', '/api/ca/account/?token='.$this->token);
        $this->accounts = $response->original['accounts'];
        $this->assertEquals(true, $response->original['success']);
        echo ' - found '.count($response->original['accounts']).' accounts';
    }

    protected function getAccountCertificates()
    {
        echo PHP_EOL.__METHOD__.' Loading certificates for accounts';
        $this->accountcertificates = [];
        foreach ($this->accounts as $account) {
            $response = $this->call('GET',
                                    '/api/ca/account/'.$account['id'].'/certificate/?token='.$this->token);
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
        throw new \Exception('could not identify certificate id for account id '.$account_id.' named '.$name);
    }

    protected function selfSignCaAccountCertificates()
    {
        echo PHP_EOL.__METHOD__.' Self signing phpUnit Root CA cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'phpUnit Root CA');
        $response = $this->call('GET',
                                '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/sign?token='.$this->token);
        $this->assertEquals(true, $response->original['success']);
    }

    protected function createCertificate()
    {
        echo PHP_EOL.__METHOD__.' Creating new certificate for example.com';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $post = [
                    'name'     => 'example.com',
                    'subjects' => ['example.com', 'www.example.com', 'test.phpunit.org'],
                    'type'     => 'server',
                ];
        $response = $this->call('POST',
                                '/api/ca/account/'.$account_id.'/certificate/?token='.$this->token,
                                $post);
        $this->assertEquals(true, $response->original['success']);
    }

    protected function generateCSR()
    {
        echo PHP_EOL.__METHOD__.' Generating csr for example.com cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'example.com');
        $response = $this->call('GET',
                                '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/generaterequest?token='.$this->token);
        $this->assertEquals(true, $response->original['success']);
    }

    protected function signCSR()
    {
        echo PHP_EOL.__METHOD__.' Signing csr for example.com cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'example.com');
        $response = $this->call('GET',
                                '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/sign?token='.$this->token);
        $this->assertEquals(true, $response->original['success']);
    }

    protected function validateSignatures()
    {
        echo PHP_EOL.__METHOD__.' Validating CA and certificate signatures with openssl';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'phpUnit Root CA');
        $cacertificate = Certificate::find($certificate_id);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'example.com');
        $certificate = Certificate::find($certificate_id);
        $this->assertEquals($cacertificate->certificate, $certificate->chain);
        // I would really like to use an external tool like openssl to validate the signatures
        echo PHP_EOL.__METHOD__.' Validating CA and Cert signatures with OpenSSL';
        file_put_contents('cacert', $cacertificate->certificate);
        file_put_contents('cert', $certificate->certificate);
        $output = shell_exec('openssl verify -verbose -CAfile cacert cacert');
        $this->assertEquals('cacert: OK', trim($output));
        $output = shell_exec('openssl verify -verbose -CAfile cacert cert');
        $this->assertEquals('cert: OK', trim($output));
        unlink('cacert');
        unlink('cert');
    }

    protected function validateUserPermissions()
    {
        echo PHP_EOL.__METHOD__.' Validating user roles have proper access';
/*
        /account/
1            $api->get('', $controller.'@listAccounts');
 2           $api->get('/{id}', $controller.'@getAccount');
  3          $api->post('', $controller.'@createAccount');
   4         $api->put('/{id}', $controller.'@updateAccount');
    5        $api->delete('/{id}', $controller.'@deleteAccount'); /**/
        $this->getJWT('Manager');
        $this->validateAccountRouteAccess([
                                           1, 1, 0, 1, 0,
                                           ]);
/*      /account/{account_id}/certificate
1            $api->get('', $controller.'@listCertificates');
 2           $api->get('/{id}', $controller.'@getCertificate');
  3          $api->post('', $controller.'@createCertificate');
   4         $api->get('/{id}/generaterequest', $controller.'@certificateGenerateRequest');
1            $api->get('/{id}/sign', $controller.'@certificateSign');
 2           $api->get('/{id}/renew', $controller.'@certificateRenew');
  3          $api->get('/{id}/pkcs12', $controller.'@certificateDownloadPKCS12');
   4         $api->get('/{id}/pem', $controller.'@certificateDownloadPEM'); /**/
        $this->validateCertificateRouteAccess([
                                               1, 1, 1, 1,
                                               1, 1, 1, 1,
                                               ]);
        //
        $this->getJWT('Signer');
        $this->validateAccountRouteAccess([
                                           1, 1, 0, 0, 0,
                                           ]);
        $this->validateCertificateRouteAccess([
                                               1, 1, 1, 1,
                                               1, 1, 1, 1,
                                               ]);
        //
        $this->getJWT('Operator');
        $this->validateAccountRouteAccess([
                                           1, 1, 0, 0, 0,
                                           ]);
        $this->validateCertificateRouteAccess([
                                               1, 1, 1, 1,
                                               0, 0, 1, 1,
                                               ]);
        //
        $this->getJWT('Unauthorized');
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
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');

        echo PHP_EOL.__METHOD__.' User can list accounts: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/?token='.$this->token);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(0, count($response->original['accounts']));
        }

        echo PHP_EOL.__METHOD__.' User can view assigned account: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/'.$account_id.'/?token='.$this->token);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can create new account: '.$expected[$i];
        $post = [
                'name'           => 'phpUnitCaAccount',
                'contact'        => 'phpUnit@example.com',
                'zones'          => 'example.com',
                'crlurl'         => 'http://crl.example.com/phpunit',
                ];
        $response = $this->call('POST',
                        '/api/ca/account/?token='.$this->token,
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can edit assigned account: '.$expected[$i];
        $post = [
                'name'           => 'phpUnitCaAccount',
                'contact'        => 'phpUnit@example.com',
                'zones'          => 'example.com',
                'crlurl'         => 'http://crl.example.com/phpunit',
                ];
        $response = $this->call('PUT',
                        '/api/ca/account/'.$account_id.'/?token='.$this->token,
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }

        echo PHP_EOL.__METHOD__.' User can delete assigned account: '.$expected[$i];
        $response = $this->call('DELETE',
                        '/api/ca/account/'.$account_id.'/?token='.$this->token,
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
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'example.com');
        //
        echo PHP_EOL.__METHOD__.' User can certificates: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/'.$account_id.'/certificate/?token='.$this->token);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(0, count($response->original['certificates']));
        }
        //
        echo PHP_EOL.__METHOD__.' User can view assigned certificate: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/?token='.$this->token);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can create new certificate: '.$expected[$i];
        $post = [
                'name'             => 'phpUnit Test Cert',
                'subjects'         => '[]',
                'type'             => 'server',
                ];
        $response = $this->call('POST',
                        '/api/ca/account/'.$account_id.'/certificate/?token='.$this->token,
                        $post);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can generate csr: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/generaterequest/?token='.$this->token);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can sign csr: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/sign/?token='.$this->token);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can renew cert: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/renew/?token='.$this->token);
        if ($expected[$i++]) {
            $this->assertEquals(true, $response->original['success']);
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can view pkcs12: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/pkcs12/?token='.$this->token);
        if ($expected[$i++]) {
            // I have literally no idea how to test this response format
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
        //
        echo PHP_EOL.__METHOD__.' User can view pem: '.$expected[$i];
        $response = $this->call('GET', '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/pem/?token='.$this->token);
        if ($expected[$i++]) {
            // I have literally no idea how to test this response format
        } else {
            $this->assertEquals(401, $response->original['status_code']);
        }
    }
}

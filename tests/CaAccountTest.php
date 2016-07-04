<?php

use Illuminate\Foundation\Testing\WithoutMiddleware;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Tymon\JWTAuth\Facades\JWTAuth;

class CaAccountTest extends TestCase
{
    protected $token;
    protected $accounts;
    protected $accountcertificates;

    public function setUp()
    {
        parent::setUp();

        //print PHP_EOL . __METHOD__ . ' generating JWT for future calls';
        $credentials = ['dn' => 'CN=phpUnit-Manager', 'password' => ''];
        $this->token = JWTAuth::attempt($credentials);

        //print PHP_EOL . __METHOD__ . ' loading accounts visible to phpunit-manager user';
        $response = $this->call('GET', '/api/ca/account/?token='.$this->token);
        $this->accounts = $response->original['accounts'];
        $this->assertEquals(true, $response->original['success']);
        //print PHP_EOL . __METHOD__ . ' loaded ' . count($response->original['accounts']) . ' accounts';

        //print PHP_EOL . __METHOD__ . ' grabbing certificates for each account';
        $this->accountcertificates = [];
        foreach ($this->accounts as $account) {
            $response = $this->call('GET',
                                    '/api/ca/account/'.$account['id'].'/certificate/?token='.$this->token);
            $this->assertEquals(true, $response->original['success']);
            $this->accountcertificates[$account['id']] = $response->original['certificates'];
            echo PHP_EOL.__METHOD__.' loaded '.count($response->original['certificates']).' in account '.$account['id'];
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

    public function testSelfSignCaAccountCertificates()
    {
        echo PHP_EOL.__METHOD__.' self signing phpUnit Root CA cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'phpUnit Root CA');
        $this->assertEquals(1, $account_id);
        $this->assertEquals(1, $certificate_id);
        $response = $this->call('GET',
                                '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/sign?token='.$this->token);
        //\metaclassing\Utility::dumper($response->original);
        $this->assertEquals(true, $response->original['success']);
    }

    public function testCreateCertificate()
    {
        echo PHP_EOL.__METHOD__.' creating new certificate for example.com';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $post = [
                    'name'     => 'example.com',
                    'subjects' => ['example.com', 'www.example.com', 'test.phpunit.org'],
                    'type'     => 'server',
                ];
        \metaclassing\Utility::dumper($post);
        $response = $this->call('POST',
                                '/api/ca/account/'.$account_id.'/certificate/?token='.$this->token,
                                $post);
        \metaclassing\Utility::dumper($response->original);
        $this->assertEquals(true, $response->original['success']);
    }

    public function testGenreateCSR()
    {
        echo PHP_EOL.__METHOD__.' generating csr for example.com cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'example.com');
        $response = $this->call('GET',
                                '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/generaterequest?token='.$this->token);
        \metaclassing\Utility::dumper($response->original);
        $this->assertEquals(true, $response->original['success']);
    }

    public function testSignCSR()
    {
        echo PHP_EOL.__METHOD__.' signing csr for example.com cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'example.com');
        $response = $this->call('GET',
                                '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/sign?token='.$this->token);
        \metaclassing\Utility::dumper($response->original);
        $this->assertEquals(true, $response->original['success']);
    }
}

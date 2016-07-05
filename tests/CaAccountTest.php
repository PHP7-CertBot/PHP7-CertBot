<?php

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
        // Seed our test data, this entire test is wrapped in a transaction so will be auto-removed
        $this->seedUserAccounts();
        $this->seedCaAccounts();
        $this->seedBouncerUserRoles();
        // Get a JWT for the authorized user in our web service
        $this->getJWT();
        $this->getAccounts();
        $this->getAccountCertificates();
        // Self sign our CA account so we can use it
        $this->selfSignCaAccountCertificates();
        // Try to make a new certificate signed by our CA
        $this->createCertificate();
        $this->getAccountCertificates();
        $this->generateCSR();
        $this->signCSR();
        // Get the cert we just created and signed, ensure it is signed by our CA
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'phpUnit Root CA');
        $cacertificate = Certificate::find($certificate_id);
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'example.com');
        $certificate = Certificate::find($certificate_id);
        file_put_contents('cacert', $cacertificate->certificate);
        file_put_contents('cert', $certificate->certificate);
        $this->assertEquals($cacertificate->certificate, $certificate->chain);
    }

    protected function seedUserAccounts()
    {
        $types = [
                 'Manager',
                 'Signer',
                 'Operator',
                 'Unauthorized',
                 ];
        foreach ($types as $id => $type) {
            User::create( [
                          'username' => 'phpUnit-'.$type,
                          'dn'       => 'CN=phpUnit-'.$type,
                          'password' => bcrypt(''),
                          ] );
        }
    }

    protected function seedCaAccounts()
    {
        $account     =     Account::create( [
                                            'name'           => 'phpUnitCaAccount',
                                            'contact'        => 'phpUnit@example.com',
                                            'zones'          => 'example.com',
                                            'crlurl'         => 'http://crl.example.com/phpunit',
                                            'status'         => 'test',
                                            'created_at'     => '2016-07-04 13:17:24',
                                            ] );
        print PHP_EOL . __METHOD__ . ' created account id ' . $account->id; //\metaclassing\Utility::dumper($account);

        $certificate = $account->certificates()->create( [
                                            'account_id'       => $account->id,
                                            'name'             => 'phpUnit Root CA',
                                            'subjects'         => '[]',
                                            'type'             => 'ca',
                                            'publickey'        => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqce4eXa55Toc0bKuCFUd
5UtamI5w8v9n13cgbfgnSSItkSi1SyuzTNmt54y+BsN0E6FHWZKmCZFoXsF5WBpA
2n1XekEJZs6mbEL2E5QavxWFdf7bjsnGDR/AYM/D+75c0qJ5bYB7fFutjW4mjO6J
A9OXKnBl75nosLw+yeLa/GvtDuXGTomjEICjiCZJKkwP9jLav3ISfjVmmPTzkigW
roBcfioNB5orHB+yBEWAEf3zBgBUPyLuehhppquVTBa10m6ufXO0E7pUza8WyskS
0RNqVbKXR+srSnW3nvFjgZq+dajNRkUoxOcFzohNxgJ1qgfX39iAGeqc4G1EK0pf
RQIDAQAB
-----END PUBLIC KEY-----',
                                              'privatekey'     => '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqce4eXa55Toc0bKuCFUd5UtamI5w8v9n13cgbfgnSSItkSi1
SyuzTNmt54y+BsN0E6FHWZKmCZFoXsF5WBpA2n1XekEJZs6mbEL2E5QavxWFdf7b
jsnGDR/AYM/D+75c0qJ5bYB7fFutjW4mjO6JA9OXKnBl75nosLw+yeLa/GvtDuXG
TomjEICjiCZJKkwP9jLav3ISfjVmmPTzkigWroBcfioNB5orHB+yBEWAEf3zBgBU
PyLuehhppquVTBa10m6ufXO0E7pUza8WyskS0RNqVbKXR+srSnW3nvFjgZq+dajN
RkUoxOcFzohNxgJ1qgfX39iAGeqc4G1EK0pfRQIDAQABAoIBAG27jjnDSMclVjca
m2z7RoVKvNVZSxtjhEQ41Jb/CrU0B+uIOhTJu+txzfqYdsF8VmvRk4ILTJFmj+Se
e8U7wqr01DNKEb+G1P2oEc/5q4fRax8mh9W0B/O3j+mCn5L4KJpjNMRXhHiN8JA2
n2f7TEdS3KMrXlcMTN7d7F8j5pG6SfGlVXJRJqosgU2ihVzNDmjbGWulWY8r7ZM1
8ETF7uBrmoPzC0Fch/GY28NZu4jNjRauqhERDN7sqAaBuJR+DuuN174gZ3k9sMNQ
pFRNCA2ZLwlQ0rfCq1CvzZfEHAiiYnNZROR6/UIGe+wSkB3j0wejoB7FJwRRB9Gn
PfTiVwkCgYEA2722Hw8pNRAhOSd6RhnyURnIVQyvacAb90he0OCmixjCVSMVpiqB
pwc0yLZnKpMH8jEKIC0zNQPgDrT5dPclgTUaqoI8cF77EZ7u/wNRggEHxjAW+fVl
rfSRCKGlWMLTTUD/eUqz5ct15Dya+4ZP58wNoD8uOjC1UQoRCrrMzy8CgYEAxcuQ
VYz2XlcX0yN/mL8uS8PPHMAmDAN8AOCDvdfxYWKxsaJi3cDZRDwsPFsSLwrkB6XV
kynjEbyPUZTXch06MW0CkxjK/+jipHG36W4h8rqxCr37qULfNUxZe5u6nn9m7fMj
GHQaqUOpD2AD2eQyJMg3TwbIxWBUZXuW1rhx+8sCgYAXhwt97diiptR30yNDaDnK
tzD88jvB3eDgrC4CvVr3n7IG/Zeuz/RL1viu2ODY7R83rkqAQXavIXgW+weOn3uz
huURBprECVdmfpbmVQugGM4lSTbckorNglcZDn2usEWBiwkPipESdKNtyZNqhOn/
TpjS5JDliBuRzrseY/vT3wKBgG9+VbfDo8R993IO2ofxjFks4Pxl24x+ElI0PE6x
AOFSTrPAw1YYtN/fw1eqRk+6JduhwQgZXmPLFEZ6Tg+HJhxiREdCfHtQfSEQ8Qhm
CkDWt6FEgi1hAoz6op4opENfsVeD7E6Gc9jhyNRf3Qvfs9xD99lWC6omqKwjxFz4
z1eNAoGBAM6yA62xg8R6PI0ghSB2Y+qIzUGI+pCkv6vwhwYVfJFQ2UqgqBllOifW
uJ/D12zfRBGJpzLG2HJJXsOPgl13XexBjOV/+Cy9OCYXCakuzYYKtfkbvdguMZQR
H+0z5lB2fHlvJ2tJLknY1MfZ704MMsq/L6UaKDfjSokQwP82UGAl
-----END RSA PRIVATE KEY-----',
                                              'created_at'     => '2016-07-04 13:17:24',
                                                    ] );
        $account->certificate_id = $certificate->id;
/**/
        $account->save();
    }

    protected function seedBouncerUserRoles()
    {
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

    protected function getJWT()
    {
        //print PHP_EOL . __METHOD__ . ' generating JWT for future calls';
        $credentials = ['dn' => 'CN=phpUnit-Manager', 'password' => ''];
        $this->token = JWTAuth::attempt($credentials);
    }

    protected function getAccounts()
    {
        //print PHP_EOL . __METHOD__ . ' loading accounts visible to phpunit-manager user';
        $response = $this->call('GET', '/api/ca/account/?token='.$this->token);
        $this->accounts = $response->original['accounts'];
        $this->assertEquals(true, $response->original['success']);
        //print PHP_EOL . __METHOD__ . ' loaded ' . count($response->original['accounts']) . ' accounts';
    }

    protected function getAccountCertificates()
    {
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

    protected function selfSignCaAccountCertificates()
    {
        echo PHP_EOL.__METHOD__.' self signing phpUnit Root CA cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'phpUnit Root CA');
        $response = $this->call('GET',
                                '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/sign?token='.$this->token);
        //\metaclassing\Utility::dumper($response->original);
        $this->assertEquals(true, $response->original['success']);
    }

    protected function createCertificate()
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

    protected function generateCSR()
    {
        echo PHP_EOL.__METHOD__.' generating csr for example.com cert';
        $account_id = $this->getAccountIdByName('phpUnitCaAccount');
        $certificate_id = $this->getAccountCertificateIdByName($account_id, 'example.com');
        $response = $this->call('GET',
                                '/api/ca/account/'.$account_id.'/certificate/'.$certificate_id.'/generaterequest?token='.$this->token);
        \metaclassing\Utility::dumper($response->original);
        $this->assertEquals(true, $response->original['success']);
    }

    protected function signCSR()
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

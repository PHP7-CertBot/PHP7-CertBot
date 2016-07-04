<?php

use App\Ca\Account;
use App\Ca\Certificate;
use Illuminate\Database\Seeder;

class CaAccountTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        DB::table('ca_accounts')->insert([
            'id'             => 1,
            'name'           => 'phpUnitCaAccount',
            'contact'        => 'phpUnit@example.com',
            'zones'          => 'example.com',
            'certificate_id' => '1', // Linked CA certificate used for signing
            'crl'            => '',
            'crlurl'         => 'http://crl.example.com/phpunit',
            'status'         => 'test',
            'created_at'     => '2016-07-04 13:17:24',
        ]);
        // Create our test CA certificate to self-sign in unit tests
        DB::table('ca_certificates')->insert([
            'id'               => 1,
            'account_id'       => 1,
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
        ]);
    }
}

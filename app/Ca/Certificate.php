<?php

namespace App\Ca;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Certificate extends Model
{
    use SoftDeletes;
    protected $table = 'ca_certificates';
    protected $fillable = ['name', 'subjects', 'type'];

    // Get the ACME Account this certificate belongs to
    public function account()
    {
        return $this->belongsTo(Account::class);
    }

    // This sets our RSA key pair for request signing
    public function generateKeys($size = 2048)
    {
        $rsaKeyGen = new \phpseclib\Crypt\RSA();
        $rsaKeyPair = $rsaKeyGen->createKey($size);
        $this->publickey = $rsaKeyPair['publickey'];
        $this->privatekey = $rsaKeyPair['privatekey'];
        // Blank out our CSR, cert, and chain if we generate new keys
        $this->request = '';
        $this->certificate = '';
        $this->chain = '';
        $this->status = 'new';
        $this->save();
    }

    public function subjectsArray()
    {
        return preg_split('/\s+/', $this->subjects);
    }

    public function subjectAlternativeNames($subjects)
    {
        $san = [];
        foreach ($subjects as $subject) {
            if (! $subject || ! trim($subject)) {
                continue;
            } elseif (filter_var($subject, FILTER_VALIDATE_EMAIL)) {
                $san[] = ['rfc822Name'    => $subject];
            } elseif (filter_var($subject, FILTER_VALIDATE_IP)) {
                $san[] = ['iPAddress'    => $subject];
            } else {
                $san[] = ['dNSName'        => $subject];
            }
        }

        return $san;
    }

    // This sets our RSA key pair for request signing
    public function generateRequest()
    {
        // Load our public and private keys into RSA objects
        $rsaPublicKey = new \phpseclib\Crypt\RSA();
        $rsaPublicKey->loadKey($this->publickey);
        $rsaPrivateKey = new \phpseclib\Crypt\RSA();
        $rsaPrivateKey->loadKey($this->privatekey);
        // Create a new certificate signing request with our key pair
        $csr = new \phpseclib\File\X509();
        $csr->setPublicKey($rsaPublicKey);
        $csr->setPrivateKey($rsaPrivateKey);
        // Craft the DN as CN=nameOfCertificate
        $subjects = $this->subjectsArray();
        $dn = 'CN='.$subjects[0];
        $csr->setDN($dn);
        // Sign our CSR with the certificates private key
        $signedCSR = $csr->signCSR('sha256WithRSAEncryption');
        // phpseclib is picky about setting X.509v3 extended attributes in a newly signed CSR, so load it again
        $csr->loadCSR($signedCSR);
        // Set the proper x509v3 attributes for each TYPE of certificate
        if ($this->type == 'ca') {
            $csr->setExtension('id-ce-basicConstraints', ['cA' => true], 1);
        } elseif ($this->type == 'user') {
            //add /emailAddress=metaclassing@nixvm to DN
            $dn .= '/emailAddress='.$subjects[1];
            $csr->setDN($dn);
            $csr->setExtension('id-ce-basicConstraints', ['cA' => false], 1);
            $csr->setExtension('id-ce-keyUsage', ['keyEncipherment', 'nonRepudiation', 'digitalSignature']);
            $csr->setExtension('id-ce-extKeyUsage', ['id-kp-emailProtection', 'id-kp-clientAuth']);
            $csr->setExtension('netscape-cert-type', ['Email', 'SSLClient']);
        } elseif ($this->type == 'server') {
            $csr->setExtension('id-ce-keyUsage', ['keyEncipherment', 'nonRepudiation', 'digitalSignature']);
            $csr->setExtension('id-ce-extKeyUsage', ['id-kp-serverAuth']);
            $altnames = $this->subjectAlternativeNames($this->subjectsArray());
            $csr->setExtension('id-ce-subjectAltName', $altnames);
        } else {
            throw new \Exception('Unsupported certificate type '.$this->type);
        }
        // Sign it again now that the x509 v3 attributes are all added
        $signedCSR = $csr->signCSR('sha256WithRSAEncryption');
        // Save the CSR to our database record
        $this->request = $csr->saveCSR($signedCSR);
        $this->status = 'unsigned';
        $this->save();
    }

    // Export the signed cert AND private key encrypted in PKCS12 format
    public function generateDownloadPKCS12($password = null)
    {
        // extract the intermediate certificate authorities chain
        $regex = '/(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/si';
        if (preg_match_all($regex, $this->chain, $hits)) {
            $extra = [
                    'extracerts' => $hits[0],
                    ];
        }
        // convert our pem private key to openssl private key object type
        $opensslprivatekey = openssl_pkey_get_private($this->privatekey);
        // generate the cert, private key, and chain as an encrypted pkcs12 file
        $success = openssl_pkcs12_export($this->certificate, $pkcs12, $opensslprivatekey, $password, $extra);
        if (! $success) {
            throw new \Exception('openssl failed to export the certificate in pkcs12 format');
        }

        return $pkcs12;
    }

    public function updateExpirationDate()
    {
        $cert = new \phpseclib\File\X509();
        $cert->loadX509($this->certificate);
        $this->expires = \DateTime::createFromFormat('D, d M Y H:i:s O',
                                                    $cert->currentCert['tbsCertificate']['validity']['notAfter']['utcTime']);
        $this->save();

        return $this->expires;
    }
}

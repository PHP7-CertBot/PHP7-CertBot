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

namespace App\Ca;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @SWG\Definition(
 *   definition="CaCertificate",
 *   required={"name", "subjects", "type"},
 * )
 **/
class Certificate extends Model implements \OwenIt\Auditing\Contracts\Auditable
{
    use SoftDeletes;
    use \OwenIt\Auditing\Auditable;

    protected $table = 'ca_certificates';
    protected $fillable = ['name', 'subjects', 'type', 'request'];
    protected $hidden = ['publickey', 'privatekey', 'request', 'certificate', 'chain', 'deleted_at'];
    protected $casts = [
        'subjects' => 'array',
    ];
    /**
     * @SWG\Property(property="id", type="integer", format="int64", description="Unique identifier for the account id")
     * @SWG\Property(property="name", type="string", description="Name of this certificate")
     * @SWG\Property(property="subjects", type="array", items={}, description="array of at least one CN followed by subject alternative names for this certificate")
     * @SWG\Property(property="type",type="string",enum={"server", "ca", "user"},description="Type of certificate, intended use, template to use")
     * @SWG\Property(property="expires",type="string",format="date-format",description="Date the current certificate expires if applicable")
     * @SWG\Property(property="status", type="string", enum={"new", "unsigned", "signed"}, description="status of this certificate, new unsigned signed etc")
     * @SWG\Property(property="created_at",type="string",format="date-format",description="Date this interaction was created")
     * @SWG\Property(property="updated_at",type="string",format="date-format",description="Date this interaction was last updated")
     * @SWG\Property(property="deleted_at",type="string",format="date-format",description="Date this interaction was deleted")
     **/

    // This overrides the parent boot function and adds
    // a complex custom validation handler for on-saving events
    protected static function boot()
    {
        parent::boot();
        static::saving(function ($certificate) {
            return $certificate->validate();
        });
    }

    // Basic certificate validation logic
    protected function validate()
    {
        // subjects are a STRING, try to handle it silently
        if (is_string($this->subjects)) {
            // Handle comma delimited values, these come from swaggerUI unfortunately
            if (strpos($this->subjects, ',') !== false) {
                $this->subjects = explode(',', $this->subjects);
            } else {
                // This is bad, but I would rather make the interface easy to use.
                $this->subjects = [$this->subjects];
            }
        }

        // if the certificates are NOT an array, scream for help
        if (! is_array($this->subjects)) {
            throw new \Exception('Certificate validation failed, subjects is not an array');
        }

        return true;
    }

    // Get the CA Account this certificate belongs to
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
        if (! $this->publickey) {
            throw new \Exception('private key is blank, did you generate keys or set current ones?');
        }
        if (! $this->privatekey) {
            throw new \Exception('private key is blank, did you generate keys or set current ones?');
        }
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
        $subjects = $this->subjects;
        $dn = 'CN='.$subjects[0];
        $csr->setDN($dn);
        // Sign our CSR with the certificates private key
        $signedCSR = $csr->signCSR('sha256WithRSAEncryption');
        // phpseclib is picky about setting X.509v3 extended attributes in a newly signed CSR, so load it again
        $csr->loadCSR($signedCSR);
        // Set the proper x509v3 attributes for each TYPE of certificate
        if ($this->type == 'ca') {
            $dn = 'CN='.$this->name;
            $csr->setDN($dn);
            $csr->setExtension('id-ce-basicConstraints', ['cA' => true], 1);
        } elseif ($this->type == 'user') {
            //add /emailAddress=Metaclassing@nixvm to DN
            //$dn .= '/emailAddress='.$subjects[1];
            $csr->setDN($dn);
            $csr->setExtension('id-ce-basicConstraints', ['cA' => false], 1);
            $csr->setExtension('id-ce-keyUsage', ['keyEncipherment', 'nonRepudiation', 'digitalSignature']);
            $csr->setExtension('id-ce-extKeyUsage', ['id-kp-emailProtection', 'id-kp-clientAuth']);
            $csr->setExtension('netscape-cert-type', ['Email', 'SSLClient']);
            // This awful Microsoft OID is the magic custom sauce to match active directory user principal names
            $altnames = [
                            [
                                'otherName' => [
                                    'type-id' => '1.3.6.1.4.1.311.20.2.3',
                                    'value'   => [
                                          'utf8String' => $subjects[1],
                                     ],
                                 ],
                             ],
                        ];
            $csr->setExtension('id-ce-subjectAltName', $altnames);
        } elseif ($this->type == 'server') {
            $csr->setExtension('id-ce-keyUsage', ['keyEncipherment', 'nonRepudiation', 'digitalSignature']);
            $csr->setExtension('id-ce-extKeyUsage', ['id-kp-serverAuth']);
            $altnames = $this->subjectAlternativeNames($this->subjects);
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
        $extra = [];
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

    public function getPrivateKeyHash()
    {
        $lines = explode(PHP_EOL, $this->privatekey);
        // remove the ----- lines before and after the b64 key
        array_shift($lines);
        array_pop($lines);
        $pem = '';
        foreach ($lines as $line) {
            $pem .= trim($line);
        }
        $der = base64_decode($pem);

        return md5($der);
    }
}

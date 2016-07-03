<?php

namespace App\Ca;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Account extends Model
{
    use SoftDeletes;
    protected $table = 'ca_accounts';
    protected $fillable = ['name', 'contact', 'zones', 'certificate_id', 'crlurl'];

    private $client;
    private $messages;

    public function log($message = '')
    {
        if ($message) {
            $this->messages[] = $message;
            file_put_contents(storage_path('logs/accountclient.log'),
                                \metaclassing\Utility::dumperToString($message),
                                FILE_APPEND | LOCK_EX
                            );
        }

        return $this->messages;
    }

    public function certificates()
    {
        return $this->hasMany(Certificate::class);
    }

    public function signCertificate($certificate)
    {
        $this->log('beginning signing process for certificate id '.$certificate->id);

        // Grab our CA certificate record
        $cacertificate = Certificate::find($this->certificate_id);

        // Mandatory things required for us to sign a cert with our authority
        if (!$cacertificate->privatekey) {
            throw new \Exception('Certificate authority unable to sign due to missing private key');
        }
        if (!$cacertificate->certificate) {
            throw new \Exception('Certificate authority unable to sign due to missing certificate');
        }

        $caPrivateKey = new \phpseclib\Crypt\RSA();
        $caPrivateKey->loadKey($cacertificate->privatekey);
        $ca = new \phpseclib\File\X509();
        $ca->loadX509($cacertificate->certificate);
        $ca->setPrivateKey($caPrivateKey);

        if (!$ca->dn) {
            throw new \Exception('Could not read certificate authority issuer DN');
        }

        // Load up our CSR and update its attributes
        $X509 = new \phpseclib\File\X509();
        $X509->loadCSR($certificate->request);            // Load the CSR back up so we can set extended attributes
        $X509->setStartDate('-1 day');                        // Make it valid from yesterday...
        if ($certificate->type == 'ca') {
            $X509->setEndDate('+ 10 years');                // Set a 10 year expiration on CA certs
            $X509->setExtension('id-ce-basicConstraints', ['cA' => true, 'pathLenConstraint' => 0], 1);
        } elseif ($certificate->type == 'user') {
            $X509->setEndDate('+ 3 years');                    // Or a 3 year expiration on user certs
            $X509->setExtension('id-ce-basicConstraints', ['cA' => false], 1);
        } else {
            $X509->setEndDate('+ 3 months');                // Or a 3 month expiration on server certs
            $X509->setExtension('id-ce-basicConstraints', ['cA' => false], 1);
        }
        $X509->setSerialNumber($certificate->id, 10);        // Use our ID number in the database, base 10 (decimal) notation

        if ($this->caurl) {
            $X509->setExtension('id-ce-cRLDistributionPoints',
                                [['distributionPoint' => ['fullName' => [['uniformResourceIdentifier' => $this->caurl]]]]]
                                );
        }
        $SIGNEDCERT = $X509->sign($ca, clone $X509, 'sha256WithRSAEncryption');
        $certificate->certificate = $X509->saveX509($SIGNEDCERT);
        $certificate->updateExpirationDate();
        $certificate->chain = $cacertificate->certificate;
        if ($cacertificate->chain) {
            $certificate->chain .= PHP_EOL.$cacertificate->chain;
        }
        $certificate->save();

        $this->log('completed signing process for certificate id '.$certificate->id);

        return true;
    }

    public function crl()
    {
        /*
        // Load up phpseclib
        set_include_path( get_include_path() . PATH_SEPARATOR . BASEDIR . "/include/phpseclib-master" );
        require_once("File/X509.php");
        require_once("File/ASN1.php");
        require_once("File/ASN1/Element.php");
        require_once("Crypt/RSA.php");
        require_once("Crypt/Hash.php");
        require_once("Math/BigInteger.php");

        $CA = array();      // Prepare our certificate authority for signing
        $CA["asciikey"      ] = file_get_contents(CAKEY);
        if (!$CA["asciikey"])   { $this->error("Could not load CA key"          ); return 0; }
        $CA["privkey"       ] = new phpseclib\Crypt\RSA();
        $CA["privkey"       ]->loadKey( $CA["asciikey"] );      // Load our CA key to sign with
        $CA["asciicert"     ] = $this->read_x509_file(CACERT);
        if (!$CA["asciicert"])  { $this->error("Could not load CA cert"         ); return 0; }
        $CA["cert"          ] = new phpseclib\File\X509();
        $CA["cert"          ]->loadX509( $CA["asciicert"] );    // Load our CA cert and public key
        $CA["cert"          ]->setPrivateKey($CA["privkey"]);
        if (!$CA["cert"]->dn)   { $this->error("Could not read issuer DN!"      ); return 0; }

        // Build the (empty) certificate revocation list.
        $CRL = new phpseclib\File\X509();
        $CRL->loadCRL(
                $CRL->saveCRL(
                    $CRL->signCRL($CA["cert"], $CRL, "sha256WithRSAEncryption")
                )
        );

        // Find and revoke all certificate where revoked = yes
        $REVOKED = $this->search( array("revoked" => "yes") );
        foreach ($REVOKED as $REVCERTID)
        {
            $CRL->setRevokedCertificateExtension($REVCERTID, "id-ce-cRLReasons", "privilegeWithdrawn");
        }

        // Sign the CRL.
        $SERIAL = time();
        $CRL->setSerialNumber($SERIAL, 10);
        $CRL->setEndDate("+1 years");
        $SIGNEDCRL = $CRL->signCRL($CA["cert"], $CRL, "sha256WithRSAEncryption");
        return $CRL->saveCRL($SIGNEDCRL);
        */
    }
}

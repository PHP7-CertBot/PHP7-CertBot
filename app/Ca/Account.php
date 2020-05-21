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
use Illuminate\Support\Facades\Log;

/**
 * @SWG\Definition(
 *   definition="CaAccount",
 *   required={"name", "contact", "zones"},
 * )
 **/
class Account extends Model implements \OwenIt\Auditing\Contracts\Auditable
{
    use SoftDeletes;
    use \OwenIt\Auditing\Auditable;

    protected $table = 'ca_accounts';
    protected $fillable = ['name', 'contact', 'zones', 'certificate_id', 'crlurl'];
    protected $hidden = ['crl', 'deleted_at'];
    /**
     * @SWG\Property(property="id", type="integer", format="int64", description="Unique identifier for the account id")
     * @SWG\Property(property="name", type="string", description="Name of this account")
     * @SWG\Property(property="contact", type="string", description="email address for account contact")
     * @SWG\Property(property="zones", type="string", description="List of zones this account is authorized to issue certificates")
     * @SWG\Property(property="certificate_id", type="integer", description="ID of CA certificate object used for signing")
     * @SWG\Property(property="crlurl", type="string", description="Fully qualified URL of certificate revocation list")
     * @SWG\Property(property="status", type="string", description="status of this account, not currently used for anything")
     * @SWG\Property(property="created_at",type="string",format="date-format",description="Date this interaction was created")
     * @SWG\Property(property="updated_at",type="string",format="date-format",description="Date this interaction was last updated")
     * @SWG\Property(property="deleted_at",type="string",format="date-format",description="Date this interaction was deleted")
     **/
    private $messages;

    public function log($message = '')
    {
        if ($message) {
            $this->messages[] = $message;
            file_put_contents(storage_path('logs/accountclient.log'),
                                \Metaclassing\Utility::dumperToString($message).PHP_EOL,
                                FILE_APPEND | LOCK_EX
                            );
            Log::info($message);
        }

        return $this->messages;
    }

    public function certificates()
    {
        return $this->hasMany(Certificate::class);
    }

    public function selfSignCertificate($certificate, $starttime = '-1 day', $endtime = null)
    {
        if (! $endtime) {
            $endtime = '+ 30 years';
        }
        $this->log('selfsign generating keys');
        $PRIVKEY = new \phpseclib\Crypt\RSA();
        $PRIVKEY->loadKey($certificate->privatekey);
        $PUBKEY = new \phpseclib\Crypt\RSA();
        $PUBKEY->loadKey($certificate->publickey);

        // Create a new SUBJECT
        $this->log('selfsign generating certificate');
        $X509 = new \phpseclib\File\X509();
        $X509->setPrivateKey($PRIVKEY);
        $X509->setPublicKey($PUBKEY);
        $X509->setDN('CN='.$this->name);
        $X509->setStartDate($starttime);
        $X509->setEndDate($endtime);
        $X509->setSerialNumber($certificate->id, 10);
        $X509->setExtension('id-ce-basicConstraints', ['cA' => true], 1);
        $X509->makeCA();

        $this->log('selfsign signing');
        $CERT = $X509->sign($X509, clone $X509, 'sha256WithRSAEncryption');

        $this->log('selfsign reloading cert');
        $X509 = new \phpseclib\File\X509();
        $X509->loadX509($CERT);
        $X509->setExtension('id-ce-basicConstraints', ['cA' => true], 1);
        $X509->makeCA();

        $this->log('selfsign reloading issuer');
        $ISSUER = new \phpseclib\File\X509();
        $ISSUER->loadX509($CERT);
        $ISSUER->setPrivateKey($PRIVKEY);
        $ISSUER->setDN($X509->getDN());
        $ISSUER->makeCA();

        $this->log('selfsign signing self with reload');
        $SIGNEDCERT = $X509->sign($ISSUER, clone $X509, 'sha256WithRSAEncryption');
        $this->log('selfsign signed');
        $certificate->certificate = $X509->saveX509($SIGNEDCERT);
        $this->log('selfsign updating expiration date');
        $certificate->updateExpirationDate();
        $certificate->status = 'signed';
        $this->log('selfsign saving cert');
        $certificate->save();

        if (! $certificate->certificate) {
            throw new \Exception('Certificate signing process failed, certificate is false');
        }

        $this->log('self signing complete');

        return true;
    }

    public function getCaForSigning($cacertificate)
    {
        // Mandatory things required for us to sign a cert with our authority
        if (! $cacertificate->privatekey) {
            throw new \Exception('Certificate authority unable to sign due to missing private key');
        }
        if (! $cacertificate->certificate) {
            throw new \Exception('Certificate authority unable to sign due to missing certificate');
        }

        $caPrivateKey = new \phpseclib\Crypt\RSA();
        $caPrivateKey->loadKey($cacertificate->privatekey);

        $ca = new \phpseclib\File\X509();
        $ca->loadX509($cacertificate->certificate);
        $ca->setPrivateKey($caPrivateKey);

        // Last minute error checking
        if (empty($ca->dn)) {
            throw new \Exception('Could not read certificate authority issuer DN');
        }

        return $ca;
    }

    public function prepareCertificateForSigning($certificate, $starttime, $endtime)
    {
        $certificate->certificate = '';

        if (! $certificate->request) {
            throw new \Exception('Certificate does not have a valid request to sign');
        }

        // Load up our CSR and update its attributes
        $X509 = new \phpseclib\File\X509();
        $X509->loadCSR($certificate->request);            // Load the CSR back up so we can set extended attributes

        // calculate start and end time validity for certificates
        if (! $endtime) {
            if ($certificate->type == 'ca') {
                $endtime = '+ 10 years';
            } elseif ($certificate->type == 'user') {
                $endtime = '+ 3 years';
            } elseif ($certificate->type == 'serverexception') {
                $endtime = '+ 5 years';
            } else {
                $endtime = '+ 3 months';
            }
        }
        $X509->setStartDate($starttime);
        $X509->setEndDate($endtime);

        // enforce the appropriate extension attributes for certificate types
        if ($certificate->type == 'ca') {
            $X509->setExtension('id-ce-basicConstraints', ['cA' => true, 'pathLenConstraint' => 0], 1);
        } elseif ($certificate->type == 'user') {
            $X509->setExtension('id-ce-basicConstraints', ['cA' => false], 1);
        } else {
            $X509->setExtension('id-ce-basicConstraints', ['cA' => false], 1);
        }

        // Use our ID number in the database, base 10 (decimal) notation
        $X509->setSerialNumber($certificate->id, 10);

        /*
        // If there is signed by a CA with a CRL URL set that in this certificate
        if ($this->caurl) {
            $X509->setExtension('id-ce-cRLDistributionPoints',
                                [['distributionPoint' => ['fullName' => [['uniformResourceIdentifier' => $this->caurl]]]]]
                                );
        }
        /**/
        return $X509;
    }

    public function signCertificate($certificate, $starttime = '-1 day', $endtime = null)
    {
        $this->log('beginning signing process for certificate id '.$certificate->id);

        // prepare ourselves for self-signed requests
        if ($certificate->id == $this->certificate_id) {
            $this->log('diverted as this is a self signing request');

            return $this->selfSignCertificate($certificate, $starttime, $endtime);
        }

        // Grab our CA certificate record
        $cacertificate = Certificate::findOrFail($this->certificate_id);
        // Get our CA X509 object ready
        $ca = $this->getCaForSigning($cacertificate);
        // Get our CERT X509 object ready
        $X509 = $this->prepareCertificateForSigning($certificate, $starttime, $endtime);
        // SIGN the CERT with the CA
        $SIGNEDCERT = $X509->sign($ca, clone $X509, 'sha256WithRSAEncryption');
        // Save the results
        $certificate->certificate = $X509->saveX509($SIGNEDCERT);
        $certificate->updateExpirationDate();
        $certificate->status = 'signed';
        // Build the chain of trust
        $certificate->chain = $cacertificate->certificate;
        // If the CA has a chain, append it to this certificates chain
        if ($cacertificate->chain) {
            $certificate->chain .= PHP_EOL.$cacertificate->chain;
        }
        $certificate->save();

        // Final error detection
        if (! $certificate->certificate) {
            throw new \Exception('Certificate signing process failed, certificate is false');
        }
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

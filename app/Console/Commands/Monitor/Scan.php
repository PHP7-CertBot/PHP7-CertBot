<?php

namespace App\Console\Commands\Monitor;

//use App\Monitor\Certificate;
use Illuminate\Console\Command;

class Scan extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'monitor:scan {--account_id=*} {--debug}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Actively connect to servers and scan their certificates for our expiration automation monitoring';

    protected $accountTypes = [\App\Acme\Account::class, \App\Ca\Account::class];

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        // scan each type of account
        foreach ($this->accountTypes as $accountType) {
            $this->debug('Scanning account types '.$accountType);
            $this->scanAccounts($accountType);
        }
    }

    protected function debug($message)
    {
        if ($this->option('debug')) {
            $this->info('DEBUG: '.$message);
        }
    }

    protected function scanAccounts($accountType)
    {
        // Find all accounts of the given type
        $accounts = $accountType::all();
        foreach ($accounts as $account) {
            // if we are only scanning a specific account id
            if (count($this->option('account_id'))) {
                $scanMe = $this->option('account_id');
                if (! is_array($scanMe)) {
                    $scanMe = [$scanMe];
                }
                // and this one is not in the list
                if (! in_array($account->id, $scanMe)) {
                    $this->debug('Skipping scan of '.$accountType.' ID '.$account->id);
                    continue;
                }
            }
            $this->info('Scanning '.$accountType.' account ID '.$account->id);
            $this->scanAccount($account);
        }
    }

    protected function scanAccount($account)
    {
        $certificates = $account->certificates()->get();
        $this->info('Account '.$account->id.' contains '.count($certificates).' certificates');
        foreach ($certificates as $certificate) {
            $this->debug('Scanning certificate ID '.$certificate->id);
            $this->scanCertificate($certificate);
        }
    }

    protected function scanCertificate($certificate)
    {
        // Skip CA certificates that are not for servers
        if (isset($certificate->type) && $certificate->type != 'server') {
            return;
        }
        $subjects = $certificate->subjects;
        $this->info('Certificate ID '.$certificate->id.' contains '.count($subjects).' subjects');
        foreach ($subjects as $subject) {
            $this->debug('Scanning subject name '.$subject);
            // EACH subject needs to be scanned by TWO sets of resolvers for SPLIT DNS
            if (substr($subject, 0, 1) != '*') {
                $this->scanSubject($subject);
                $this->scanSubject($subject, 'external');
            } else {
                $this->debug('skipping subject scan for wildcard '.$subject);
            }
        }
    }

    protected function scanSubject($subject, $splitDns = 'internal')
    {
        $nameservers = [];
        // Handle scanning externally
        if ($splitDns == 'external') {
            $nameservers = ['8.8.8.8', '8.8.4.4'];
        }
        $addresses = $this->getAddressesByName($subject, $nameservers);
        $this->info('Identified '.count($addresses).' '.$splitDns.' IPs to scan for name '.$subject);
        foreach ($addresses as $address) {
            $this->scanAddressForName($address, $subject);
        }
    }

    protected function getAddressesByName($domain, $nameservers = [])
    {
        $dnsoptions = [];
        // IF we are passed optional external resolvers, set them for use
        if ($nameservers) {
            $dnsoptions['nameservers'] = $nameservers;
        }
        $resolver = new \Net_DNS2_Resolver($dnsoptions);
        $addresses = [];
        try {
            // Get all the A records in the response, this may contain intermediate CNAME's as well!
            $response = $resolver->query($domain, 'A');
            $answers = [];
            // Make sure we have a property called answer
            if (property_exists($response, 'answer')) {
                $answers = $response->answer;
            }
            // Look through answers for IP addresses
            foreach ($answers as $answer) {
                if (property_exists($answer, 'address')) {
                    $addresses[] = $answer->address;
                }
            }
        } catch (\Exception $e) {
            // Error getting DNS answers, but skip this one because lots of names dont exist
            if ($e->getMessage() != 'DNS request failed: The domain name referenced in the query does not exist.') {
                $this->debug('dns resolution exception: '.$e->getMessage());
            }
        }

        return $addresses;
    }

    protected function scanAddressForName($address, $subject)
    {
        // TODO: check some list of TCP ports instead of JUST assuming 443 on everything.
        $ports = [443];
        foreach ($ports as $port) {
            $this->scanAddressPortForName($address, $port, $subject);
        }
    }

    protected function scanAddressPortForName($address, $port, $subject)
    {
        try {
            $x509 = $this->getOpensslX509($address, $port, $subject);
            $openssl = openssl_x509_parse($x509);
            $data = [
                      'cn'         => $openssl['subject']['CN'],
                      'san'        => $this->parseOpensslSAN($openssl),
                      'issuer'     => $openssl['issuer']['CN'],
                      'issued_at'  => date('Y-m-d H:i:s', $openssl['validFrom_time_t']),
                      'expires_at' => date('Y-m-d H:i:s', $openssl['validTo_time_t']),
                      'cert'       => $x509,
                    ];
            // Make sure the CN is not an array...
            if (is_array($data['cn'])) { $data['cn'] = json_encode($data['cn']); }
        } catch (\Exception $e) {
            $this->debug('Exception getting certificate for address '.$address.' port '.$port.' subject '.$subject.' message '.$e->getMessage());

            return;
        }

        // At this point we have a parsed certificate for an address/port/subject combo. we can upsert a monitor/certificate!
        $key = [
               'ip'         => $address,
               'port'       => $port,
               'servername' => $subject,
               ];
        try {
            $certificate = \App\Monitor\Certificate::updateOrCreate($key, $data);
        } catch (\Exception $e) {
            $this->debug('Exception doing update or create for cert monitor');
            dump($key);
            dump($data);
            exit(1);
        }
        // Try doing this to force the updated_at change?
        $certificate->scanned_at = \Carbon\Carbon::now();
        $certificate->save();
        $this->info('upserted monitor_certificate id '.$certificate->id);
    }

    protected function getOpensslx509($address, $port, $subject)
    {
        $command = 'timeout 5 openssl s_client -connect '.$address.':'.$port.' -servername '.$subject.' 2>&1 < /dev/null';
        $this->debug('Running command: '.$command);
        $output = shell_exec($command);
        $regex = '/(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/ms';
        if (! preg_match($regex, $output, $hits)) {
            throw new \Exception('Did not get certificate back from command '.$command);
        }

        return $hits[1];
    }

    protected function parseOpensslSAN($openssl)
    {
        $santext = $openssl['extensions']['subjectAltName'];
        $sanarray = explode(',', $santext);
        $subjects = [];
        foreach ($sanarray as $altname) {
            $altname = trim($altname);
            $parts = explode(':', $altname);
            $subjects[] = $parts[1];
        }

        return $subjects;
    }
}

<?php

namespace App\Console\Commands\Acme;

use App\Acme\Account;
use App\Acme\Certificate;
use Illuminate\Console\Command;

class Renew extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'acme:renew {--limit=*} {--account_id=*} {--certificate_id=*} {--debug} {--force}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Renew certificates for an account expiring in the next 60 days';

    // cache list of accounts indexed by ID
    private $accounts = [];

    // List of certificates we scan indexed by ID
    private $certificates = [];

    // number of signs we have succeeded
    private $signs = 0;
    // max limit of number of renews to attempt per execution
    private $signLimit = 10;

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
        $this->handleRateLimit();
        // handle the CLI options passed (if any)
        $this->handleAccounts();
        $this->handleCertificates();
        $this->handleAll();
        // scan selected certificates for auto renewal
        $this->scanForRenew();
    }

    protected function handleRateLimit()
    {
        $limit = $this->option('limit');
        // Always use the first limit passed
        $limit = reset($limit);
        // If the user provided us a limit then use it
        if ($limit) {
            $this->signLimit = $limit;
        }
        $this->debug('renew attempt limit is '.$this->signLimit);
    }

    protected function debug($message)
    {
        if ($this->option('debug')) {
            $this->info('DEBUG: '.$message);
        }
    }

    protected function getAccount($account_id)
    {
        // If we dont have the requested object cached, go get it
        if (! isset($this->accounts[$account_id])) {
            $account = Account::findOrFail($account_id);
            $this->accounts[$account->id] = $account;
        }

        return $this->accounts[$account_id];
    }

    protected function getCertificate($certificate_id)
    {
        // If we dont have the requested object cached, go get it
        if (! isset($this->certificates[$certificate_id])) {
            $certificate = Certificate::findOrFail($certificate_id);
            if (! is_string($certificate->expires) && is_object($certificate->expires) && method_exists($certificate->expires, 'format')) {
                $certificate->expires = $certificate->expires->format('Y-m-d-H-i-s');
            }
            $this->certificates[$certificate->id] = $certificate;
        }

        return $this->certificates[$certificate_id];
    }

    protected function handleAccounts()
    {
        // If they passed one or more account IDs queue those accounts to renew
        $accounts = $this->option('account_id');
        // this is dumb
        if (! is_array($accounts)) {
            $accounts = [$accounts];
        }
        // add each account specified to our collection
        foreach ($accounts as $account_id) {
            $account = $this->getAccount($account_id);
            $certificates = Certificate::where('account_id', $account->id)->orderBy('expires')->pluck('id');
            $this->debug('Account ID '.$account->id.' name '.$account->name.' has '.count($certificates).' certificates');
            foreach ($certificates as $certificate_id) {
                $certificate = $this->getCertificate($certificate_id);
                $this->debug('queued certificate id '.$certificate->id.' name '.$certificate->name.' for renewal, current expiration is '.$certificate->expires);
            }
        }
    }

    protected function handleCertificates()
    {
        // If they passed one or more account IDs queue those accounts to renew
        $certs = $this->option('certificate_id');
        // this is dumb
        if (! is_array($certs)) {
            $certs = [$certs];
        }
        // If they passed in just individual certificate IDs, include those in the renew too
        if (count($certs)) {
            foreach ($certs as $certificate_id) {
                $certificate = $this->getCertificate($certificate_id);
                $this->debug('queued certificate id '.$certificate->id.' name '.$certificate->name.' for renewal, current expiration is '.$certificate->expires);
            }
        }
    }

    protected function handleAll()
    {
        // If they passed one or more account IDs queue those accounts to renew
        $accounts = $this->option('account_id');
        // this is dumb
        if (! is_array($accounts)) {
            $accounts = [$accounts];
        }
        // If they passed one or more account IDs queue those accounts to renew
        $certs = $this->option('certificate_id');
        // this is dumb
        if (! is_array($certs)) {
            $certs = [$certs];
        }
        if (! count($accounts) && ! count($certs)) {
            $certificates = Certificate::select()->orderBy('expires')->pluck('id');
            foreach ($certificates as $certificate_id) {
                $certificate = $this->getCertificate($certificate_id);
                $this->debug('queued certificate id '.$certificate->id.' name '.$certificate->name.' for renewal, current expiration is '.$certificate->expires);
            }
        }
    }

    protected function daysRemaining($certificate)
    {
        $now = new \DateTime('now');
        // If they give us a string rather than datetime type, convert it to datetime
        if (is_string($certificate->expires)) {
            $expires = new \Datetime($certificate->expires);
        } else {
            $expires = $certificate->expires;
        }

        return $now->diff($expires)->format('%a');
    }

    protected function scanForRenew()
    {
        // loop through all the certs included in this run and renew them if their expiration is <= 60 days out
        //ksort($this->certificates);
        foreach ($this->certificates as $certificate_id => $certificate) {
            // Skip processing unsigned certificates
            if ($certificate->status != 'signed') {
                $this->debug('skipping unsigned certificate id '.$certificate->id.' its status is '.$certificate->status);
                continue;
            }
            // Dont sign any more per day than the alotted limit
            if ($this->signs >= $this->signLimit) {
                $this->info('Number of signed certificates has exceeded the daily limit '.$this->signs.' >= '.$this->signLimit);

                return;
            }
            $daysremaining = $this->daysRemaining($certificate);
            if ($daysremaining < 60 || $this->option('force')) {
                $this->info('Certificate id '.$certificate->id.' expires in '.$daysremaining.' days, is candidate for renewal');
                $this->signCertificate($certificate);
            } else {
                $this->debug('Certificate id '.$certificate->id.' expires in '.$daysremaining.' days, is NOT candidate for renewal');
            }
        }
    }

    protected function signCertificate($certificate)
    {
        $account = $this->getAccount($certificate->account_id);
        try {
            $this->info('Attempting to renew certificate id '.$certificate->id.' named '.$certificate->name);
            $account->signCertificate($certificate);
            // we were updated and saved in the database so reload ourselves...
            $certificate = $certificate->find($certificate->id);
            $this->info('Successfully renewed certificate id '.$certificate->id.' now expires in '.$this->daysRemaining($certificate).' days');
            $this->signs++;
        } catch (\Exception $e) {
            $this->info('Failed to renewed certificate id '.$certificate->id.' encountered exception: '.$e->getMessage());
            //dd($e->getTrace());
        }
    }
}

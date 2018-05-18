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
    protected $signature = 'acme:renew {--account_id=*} {--certificate_id=*} {--debug} {--force}';

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
        // handle the CLI options passed (if any)
        $this->handleAccounts();
        $this->handleCertificates();
        $this->handleAll();
        // scan selected certificates for auto renewal
        $this->scanForRenew();
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
            $this->certificates[$certificate->id] = $certificate;
        }

        return $this->certificates[$certificate_id];
    }

    protected function handleAccounts()
    {
        // If they passed one or more account IDs queue those accounts to renew
        if ($this->option('account_id')) {
            $account_id = $this->option('account_id');
            $account = $this->getAccount($account_id);
            $certificates = Certificate::where('account_id', $account->id)->pluck('id');
            $this->debug('Account ID '.$account->id.' name '.$account->name.' has '.count($certificates).' certificates');
            foreach ($certificates as $certificate_id) {
                $certificate = $this->getCertificate($certificate_id);
                $this->debug('queued certificate id '.$certificate->id.' name '.$certificate->name.' for renewal, current expiration is '.$certificate->expires);
            }
        }
    }

    protected function handleCertificates()
    {
        // If they passed in just individual certificate IDs, include those in the renew too
        if (count($this->option('certificate_id'))) {
            foreach ($this->option('certificate_id') as $certificate_id) {
                $certificate = $this->getCertificate($certificate_id);
                $this->debug('queued certificate id '.$certificate->id.' name '.$certificate->name.' for renewal, current expiration is '.$certificate->expires);
            }
        }
    }

    protected function handleAll()
    {
        if (! count($this->option('account_id')) && ! count($this->option('certificate_id'))) {
            $certificates = Certificate::select()->pluck('id');
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
        ksort($this->certificates);
        foreach ($this->certificates as $certificate_id => $certificate) {
            // Skip processing unsigned certificates
            if ($certificate->status != 'signed') {
                continue;
            }
            $daysremaining = $this->daysRemaining($certificate);
            if ($daysremaining < 60 || $this->option('force')) {
                $this->info('Certificate id '.$certificate->id.' expires in '.$daysremaining.' days, is candidate for renewal');
                $this->signCertificate($certificate);
                break;
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
            $this->info('Successfully renewed certificate id '.$certificate->id.' now expires in '.$this->daysRemaining($certificate).' days');
        } catch (\Exception $e) {
            $this->info('Failed to renewed certificate id '.$certificate->id.' encountered exception: '.$e->getMessage());
            //dd($e->getTrace());
        }
    }
}

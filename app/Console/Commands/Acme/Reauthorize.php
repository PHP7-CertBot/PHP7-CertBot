<?php

namespace App\Console\Commands\Acme;

use Illuminate\Console\Command;

class Reauthorize extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'acme:reauthorize {--account_id=*} {--debug}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Reauthorize all expired but still needed acme authz';

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
        // reauthorize any expired authz for previously signed certs
        $this->scanAuthzForRenew();
        // Delete old authz no longer used in any acme certs
        $this->deleteOldAuthz();
    }

    protected function debug($message)
    {
        if ($this->option('debug')) {
            $this->info('DEBUG: '.$message);
        }
    }

    protected function scanAuthzForRenew()
    {
        // If they passed one or more account IDs queue those accounts to renew
        $account_id = $this->option('account_id');
        if (is_array($account_id)) {
            $account_id = reset($account_id);
        }
        if ($account_id) {
            $accounts = [\App\Acme\Account::findOrFail($account_id)];
        } else {
            // Get all the acme accounts
            $accounts = \App\Acme\Account::all();
        }
        // Loop through the accounts and do authz renewal
        foreach ($accounts as $account) {
            $this->debug('Checking authz for acme account '.$account->id);
            // Get all certs in this acme account
            $certificates = $account->certificates()->where('status', 'signed')->get();
            foreach ($certificates as $certificate) {
                $this->debug('Checking authz for acme account '.$account->id.' certificate '.$certificate->id);
                try {
                    // Make sure all subjects have an authz
                    $account->makeAuthzForCertificate($certificate);
                    // Make sure any subjects with pending authz get solved
                    $account->solvePendingAuthzForCertificate($certificate);
                    // Check to see all subjects authz are valid or throw an exception
                    $account->validateAllAuthzForCertificate($certificate);
                } catch (\Exception $e) {
                    $this->info('Encountered exception renewing authz for acme account '.$account->id.' certificate '.$certificate->id.' with message '.$e->getMessage());
                }
            }
        }
    }

    protected function deleteOldAuthz()
    {
        $authz = \App\Acme\Authorization::all();
        foreach ($authz as $authorization) {
            $this->debug('Checking authz id '.$authorization->id.' identifier '.$authorization->identifier.' for active certificates');
            $whereRaw = "JSON_SEARCH(`subjects`, 'one', '$authorization->identifier') IS NOT NULL";
            $certs = \App\Acme\Certificate::whereRaw($whereRaw)->get();
            $this->debug('Authz id '.$authorization->id.' identifier '.$authorization->identifier.' currently used in '.$certs.' certificates');
            if (! count($certs)) {
                $this->info('Authz ID '.$authorization->id.' identifier '.$authorization->identifier.' is unused, deactivating...');
                $authorization->delete();
            }
            if (count($certs) > 1) {
                foreach ($certs as $cert) {
                    //$this->info('Authz ID '.$authorization->id.' identifier '.$authorization->identifier.' used in certificate id '.$cert->id.' with subjects '.json_encode($cert->subjects));
                }
            }
        }
    }
}

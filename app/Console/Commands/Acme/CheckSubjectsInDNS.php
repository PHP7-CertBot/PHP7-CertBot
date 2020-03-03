<?php

namespace App\Console\Commands\Acme;

use Illuminate\Console\Command;

class CheckSubjectsInDNS extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'acme:checksubjectsindns {--account_id=*} {--debug}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check all the dns subjects in certificates to make sure they actually resolve somehow';

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
        // Check certificate subjects in DNS to make sure they resolve
        $this->scanSubjectsInDNS();
    }

    protected function debug($message)
    {
        if ($this->option('debug')) {
            $this->info('DEBUG: '.$message);
        }
    }

    protected function scanSubjectsInDNS()
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
        // Loop through the accounts and do the checking
        foreach ($accounts as $account) {
            $this->debug('Checking dns records for subjects for acme account '.$account->id);
            $this->scanSubjectsInDNSAccount($account);
        }
    }

    protected function scanSubjectsInDNSAccount ($account)
    {
        // Get all certs in this acme account
        $certificates = $account->certificates()->where('status', 'signed')->get();
        foreach ($certificates as $certificate) {
            $this->debug('Checking dns records for subjects in acme account '.$account->id.' certificate '.$certificate->id);
            $hits = $this->scanSubjectsInDNSCertificate($account, $certificate);
            if (!$hits) {
                $this->info('Acme account id '.$account->id.' certificate id '.$certificate->id.' did not contain any subjects with dns records and should be deactivated!');
                // Soft delete the useless certificate
                $certificate->delete();
            }
        }
    }

    protected function scanSubjectsInDNSCertificate($account, $certificate)
    {
        // Get the subjects out of this certificate
        $subjects = $certificate->subjects;
        // Count how many subjects have dns for the cert...
        $subjectsWithDNS = 0;

        foreach ($subjects as $subject) {
            $this->debug('Checking subject for dns records: ' . $subject);
            $addresses = [];

            // hard coded internal nameservers for now
            $nameservers = ['10.252.13.133', '10.252.13.134'];
            $addresses['internal'] = $this->getAddressesByName($subject, $nameservers);
            $this->debug('Internal nameservers for subject contain ' . count($addresses) . ' records');

            // hard coded external nameservers for now
            $nameservers = ['1.1.1.1', '8.8.8.8'];
            $addresses['external'] = $this->getAddressesByName($subject, $nameservers);
            $this->debug('External nameservers for subject contain ' . count($addresses) . ' records');

            // If the subject is actually dead, maybe we should clean it up?
            if (count($addresses['internal']) == 0 && count($addresses['external']) == 0) {
                $this->info('Acme account id '.$account->id.' certificate id '.$certificate->id.' subject '.$subject.' has no dns records and should be removed!');
                // remove subject that does NOT resolve anywhere from the array... this is in testing for feature needs so dont save the changes yet
                $arraySubjects = $certificate->subjects;
                $arrayPosition = array_search($subject, $subjects);
                if ($arrayPosition !== false) {
                    unset($arraySubjects[$arrayPosition]);
                    $certificate->subjects = $arraySubjects;
                    //$certificate->save();
                }
            } else {
                $this->debug('    got dns records: '.json_encode($addresses));
                $subjectsWithDNS++;
            }
        }

        return $subjectsWithDNS;
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

}

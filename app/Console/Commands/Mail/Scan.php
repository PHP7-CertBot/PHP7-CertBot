<?php

namespace App\Console\Commands\Mail;

//use App\Monitor\Certificate;
use Illuminate\Console\Command;

class Scan extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'mail:scan {--domain=*} {--debug}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check mail records to compare with known good spf/dkim/dmarc';

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
        $domains = $this->option('domain');
        // handle empty domains
        if (! $domains) {
            echo 'no domains to scan'.PHP_EOL;
            return;
        }
        // scan each domain
        foreach ($domains as $domain) {
            $this->debug('scanning domain '.$domain);
            $this->scanDomain($domain);
        }
    }

    protected function debug($message)
    {
        if ($this->option('debug')) {
            $this->info('DEBUG: '.$message);
        }
    }

    protected function scanDomain($domain)
    {
        // find spf record
        $spfRecord = $this->getSPFRecord($domain);
        if ($spfRecord) {
            $this->info('FOUND SPF RECORD FOR DOMAIN '.$domain.' IS '.$spfRecord);
        } else {
            $this->info('COULD NOT FIND SPF RECORD FOR DOMAIN '.$domain);
        }

        // find dmarc record
        $dmarcRecord = $this->getDMARCRecord($domain);
        if ($spfRecord) {
            $this->info('FOUND SPF RECORD FOR DOMAIN '.$domain.' IS '.$spfRecord);
        } else {
            $this->info('COULD NOT FIND SPF RECORD FOR DOMAIN '.$domain);
        }

        // todo: find the dkim records... this is going to be tricky and requires we know the dkim selector...
    }

    protected function getSPFRecord($domain)
    {
        // start by grabbing all txt records for the domain
        $txtRecords = $this->getTxtRecords($domain);

        // search through all txt records for one that starts with "v=spf1 ..."
        foreach ($txtRecords as $record) {
            // handle checking each record we get back
            if (substr($record, 0, 6) == 'v=spf1') {
                return $record;
            }
        }

        return '';
    }

    protected function getDMARCRecord($domain)
    {
        // start by grabbing all txt records for the dmarc_.domain
        $txtRecords = $this->getTxtRecords('_dmarc.'.$domain);

        // search through all txt records for one that starts with "v=DMARC1; ..."
        foreach ($txtRecords as $record) {
            // handle checking each record we get back
            if (substr($record, 0, 8) == 'v=DMARC1') {
                return $record;
            }
        }

        return '';
    }

    protected function getTxtRecords($domain)
    {
        // Handle scanning externally
        $nameservers = ['1.1.1.1', '1.0.0.1'];

        // dns options used by the net dns2 resolver library
        $dnsoptions = [];

        // IF we are passed optional external resolvers, set them for use
        if ($nameservers) {
            $dnsoptions['nameservers'] = $nameservers;
        }

        // create our net dns2 resolver with options
        $resolver = new \Net_DNS2_Resolver($dnsoptions);

        // make an array of text records to get back i hope
        $txtRecords = [];

        try {
            // Get all the TXT records in the response, i dont know if there are weird caveats in this call i need to handle...
            $response = $resolver->query($domain, 'TXT');
            $answers = [];

            // Make sure we have a property called answer
            if (property_exists($response, 'answer')) {
                $answers = $response->answer;
            }

            // Look through answers for IP addresses
            foreach ($answers as $answer) {
                if (property_exists($answer, 'text')) {
                    $txtRecords[] = implode('', $answer->text);
                }
            }


        } catch (\Exception $e) {
            // Error getting DNS answers, but skip this one because lots of names dont exist
            if ($e->getMessage() != 'DNS request failed: The domain name referenced in the query does not exist.') {
                $this->debug('dns resolution exception: '.$e->getMessage());
            }
        }

        return $txtRecords;
    }

    protected function scanRecordsForMail($txtRecords)
    {
        // TODO: loop through all the records and pick out the SPF, DKIM, and DMARC records...
    }

}

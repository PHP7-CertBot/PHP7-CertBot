<?php

namespace App\Console\Commands\Ca;

use Illuminate\Console\Command;

class Certificate extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'ca:certificate {certificate_id} {--debug}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prints out a certificate with key and chain in PEM format';

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
        // Get the user inputted certificate id
        $certificate_id = $this->argument('certificate_id');
        $this->debug('Getting user requested certificate '.$certificate_id);
        // Get the certificate or bomb out
        $certificate = \App\Ca\Certificate::findOrFail($certificate_id);
        $this->debug('Retrieved certificate, maybe i will debug some details about it...');
        // Generate the PEM format
        $pem = $certificate->privatekey.PHP_EOL
             .$certificate->certificate.PHP_EOL
             .$certificate->chain.PHP_EOL;
        // Print it out
        echo $pem;
    }

    protected function debug($message)
    {
        if ($this->option('debug')) {
            $this->info('DEBUG: '.$message);
        }
    }
}

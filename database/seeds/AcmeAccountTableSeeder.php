<?php

use App\Acme\Account;
use Illuminate\Database\Seeder;

class AcmeAccountTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
		DB::table('acme_accounts')->insert([
    		'id'          => 1,
    		'name'        => 'phpUnitAcmeAccount',
			'contact'     => 'phpUnit@example.com',
			'zones'       => env('TEST_ACME_ZONES'),
			'acmecaurl'   => env('TEST_ACME_CAURL'),
            'acmelicense' => 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf',
            'authtype'    => env('TEST_ACME_AUTHTYPE'),
			'authprovider'=> env('TEST_ACME_AUTHPROVIDER'),
			'authuser'    => env('TEST_ACME_AUTHUSER'),
			'authpass'    => env('TEST_ACME_AUTHPASS'),
		]);
		$account = Account::where('name', 'phpUnitAcmeAccount')->first();
		$account->status = 'new';
		$account->generateKeys();
    }
}

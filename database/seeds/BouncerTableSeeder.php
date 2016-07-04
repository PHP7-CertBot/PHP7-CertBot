<?php

use app\User;
use Illuminate\Database\Seeder;

class BouncerTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
		// Create a new role called 'admin' that can manage all Acme and CA accounts and downstream certificates
		Bouncer::allow('admin')->to('manage', App\Ca\Account::class);
		Bouncer::allow('admin')->to('manage', App\Acme\Account::class);

		// Roles for ACME account testing
		$acme_account = App\Acme\Account::where('name', 'phpUnitAcmeAccount')->first();
		Bouncer::allow('phpunit-manager')->to('manage', $acme_account);
		Bouncer::allow('phpunit-signer')->to('sign', $acme_account);
		Bouncer::allow('phpunit-operator')->to('operate', $acme_account);

		// Roles for CA account testing
		$ca_account = App\Ca\Account::where('name', 'phpUnitCaAccount')->first();
		Bouncer::allow('phpunit-manager')->to('manage', $ca_account);
		Bouncer::allow('phpunit-signer')->to('sign', $ca_account);
		Bouncer::allow('phpunit-operator')->to('operate', $ca_account);

		// Map phpunit users to their roles
		$user = User::where('username', 'phpUnit-Manager')->first();
		Bouncer::assign('phpunit-manager')->to($user);
		$user = User::where('username', 'phpUnit-Signer')->first();
		Bouncer::assign('phpunit-signer')->to($user);
		$user = User::where('username', 'phpUnit-Operator')->first();
		Bouncer::assign('phpunit-operator')->to($user);
    }
}

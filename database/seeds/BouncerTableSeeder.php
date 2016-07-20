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
    }
}

<?php

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // create test user accounts for manaer, signer, operator, and unauthorized
        $this->call(UsersTableSeeder::class);
        // create test accounts for acme and CA
        $this->call(AcmeAccountTableSeeder::class);
        $this->call(CaAccountTableSeeder::class);
        // Grant permissions to phpunit test users on our accounts
        $this->call(BouncerTableSeeder::class);
    }
}

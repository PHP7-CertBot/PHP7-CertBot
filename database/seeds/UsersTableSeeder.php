<?php

use Illuminate\Database\Seeder;

class UsersTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
		$types = [
                     'Manager',
                     'Signer',
                     'Operator',
                 ];
		foreach( $types as $id => $type) {
	        DB::table('users')->insert([
            	'id'       => $id + 1,
            	'username' => 'phpUnit-' . $type,
            	'dn'       => 'CN=phpUnit-' . $type,
            	'password' => bcrypt(''),
            ]);
		}
    }
}

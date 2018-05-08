<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class SetAcmeAccountPublicKeyNullable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Acme account table changes
        Schema::table('acme_accounts', function (Blueprint $table) {
            $table->longtext('publickey')    // ascii armor public key pem format
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->longtext('privatekey')   // ascii armor private key pem format
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->string('status')         // account status unregistered/registered
                  ->default('unregistered')  // needs a default value now
                  ->change();
            $table->longtext('registration') // registration response from acme ca
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
        });
        // Acme certificate table changes
        Schema::table('acme_certificates', function (Blueprint $table) {
            $table->longtext('publickey')    // ascii armor public key pem format
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->longtext('privatekey')   // ascii armor private key pem format
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->string('status')         // account status unregistered/registered
                  ->default('unregistered')  // needs a default value now
                  ->change();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        //
    }
}

<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class SetAcmeAccountPublicKeyNullable extends Migration
{
    // fix a very stupid doctrine dbal bug
    public function __construct()
    {
        DB::getDoctrineSchemaManager()->getDatabasePlatform()->registerDoctrineTypeMapping('json', 'string');
    }

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
            $table->longtext('request')      // pem certificate signing request
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->longtext('certificate')  // pem certificate signed by CA
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->longtext('chain')        // pem chain of intermediate CA
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->dateTime('expires')      // datetime for expiration time
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->string('status')         // account status unregistered/registered
                  ->default('new')           // needs a default value now
                  ->change();
        });

        Schema::table('acme_authorizations', function (Blueprint $table) {
            $table->string('status')         // enum values like new, pending, valid
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            $table->dateTime('expires')      // usually authz expire after 31 days
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            // This is another doctrine dbal bug
            /*
            $table->json('challenge')        // JSON array of challenge information
                  ->nullable()               // needs to be nullable for some reason
                  ->change();
            /**/
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

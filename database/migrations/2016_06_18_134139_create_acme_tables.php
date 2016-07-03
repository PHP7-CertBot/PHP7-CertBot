<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateAcmeTables extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('acme_accounts', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');           // simple name to reference the account by
            $table->string('contact');        // email address for acme ca contact information
            $table->longtext('zones');        // list of authorized top level zones for this account to use
            $table->longtext('publickey');    // ascii armor public key pem format
            $table->longtext('privatekey');   // ascii armor private key pem format
            $table->string('acmecaurl');      // url for acme ca api to send clients to
            $table->string('acmelicense');    // url for acme ca license for account registration
            $table->string('authtype');       // dns-01 is the only option supported
            $table->string('authprovider');   // cloudflare or verisign
            $table->string('authuser');       // cloudflare email address or verisign username
            $table->string('authpass');       // cloudflare API key or verisign password
            $table->string('status');         // account status new/unregistered/registered/etc?
            $table->longtext('registration'); // registration response from acme ca
            $table->timestamps();
            $table->softDeletes();            // keep deactivated certificates in the table
        });

        Schema::create('acme_certificates', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('account_id')->unsigned();
            $table->string('name');           // simple name for the certificate
            $table->longtext('subjects');     // whitespace delimited list of subject alternative names
            $table->longtext('publickey');    // pem public key
            $table->longtext('privatekey');   // pem private key
            $table->longtext('request');      // pem certificate signing request
            $table->longtext('certificate');  // pem certificate signed by CA
            $table->longtext('chain');        // pem chain of intermediate CA
            $table->dateTime('expires');      // datetime for expiration time
            $table->string('status');         // status of the signing request
            $table->timestamps();
            $table->softDeletes();            // keep deactivated certificates in the table

            // 1:many account->certificates relationship
            $table->foreign('account_id')->references('id')->on('acme_accounts');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop('acme_certificates');
        Schema::drop('acme_accounts');
    }
}

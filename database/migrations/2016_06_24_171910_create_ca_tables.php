<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;

class CreateCaTables extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('ca_accounts', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');          // simple name for the CA
            $table->string('contact');       // contact email address or something
            $table->longtext('zones');       // zones authorized to sign for
            $table->integer('certificate_id')->unsigned();
            /*	So instead of tracking pub/priv key, csr cert and chain in our CA record
                I opted to move it into a Ca\Certificate record\
                self signed certs can reference themselves, dummy certs can be created
                for stand alone issuing CA's
            */
            $table->longtext('crl');         // calculated CRL we have from deleted certs
            $table->string('crlurl');        // url to get our CRL if not this web service
            $table->string('status');        // tbd i guess
            $table->timestamps();
            $table->softDeletes();
        });
        //DB::update('ALTER TABLE ca_accounts AUTO_INCREMENT = 10;');

        Schema::create('ca_certificates', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('account_id')->unsigned();
            $table->string('name');          // simple name for the certificate
            $table->enum('type', ['server', 'user', 'ca']); // TYPE of cert: server, user, or CA
            //$table->longtext('subjects');    // whitespace delimited subject alternative names
            $table->json('subjects');        // simple json array of subject alternative names
            $table->longtext('publickey');   // pem public key
            $table->longtext('privatekey');  // pem private key
            $table->longtext('request');     // pem certificate signing request
            $table->longtext('certificate'); // pem certificate signed by CA
            $table->longtext('chain');       // pem chain of intermediate CA
            $table->dateTime('expires');     // datetime for expiration time
            $table->string('status');        // status of the signing request
            $table->timestamps();
            $table->softDeletes();           // keep deactivated certificates in the table for REVOCATION
        });
        //DB::update('ALTER TABLE ca_certificates AUTO_INCREMENT = 10;');
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop('ca_certificates');
        Schema::drop('ca_accounts');
    }
}

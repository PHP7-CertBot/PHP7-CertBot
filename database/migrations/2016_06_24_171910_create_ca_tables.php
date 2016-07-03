<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

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
            $table->string('name');            // simple name for the CA
            $table->string('contact');        // contact email address or something
            $table->longtext('zones');        // zones authorized to sign for
            $table->integer('certificate_id')->unsigned();
            /*	So instead of tracking pub/priv key, csr cert and chain in our CA record
                I opted to move it into a Ca\Certificate record\
                self signed certs can reference themselves, dummy certs can be created
                for stand alone issuing CA's
            */
            $table->longtext('crl');        // calculated CRL we have from deleted certs
            $table->string('crlurl');        // url to get our CRL if not this web service
            $table->string('status');        // tbd i guess
            $table->timestamps();
            $table->softDeletes();
        });

        Schema::create('ca_certificates', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('account_id')->unsigned();
            $table->string('name');            // simple name for the certificate
            $table->string('type');            // TYPE of cert: server, user, or CA
            $table->longtext('subjects');    // json array of subject alternative names
            $table->longtext('publickey');    // pem public key
            $table->longtext('privatekey');    // pem private key
            $table->longtext('request');    // pem certificate signing request
            $table->longtext('certificate'); // pem certificate signed by CA
            $table->longtext('chain');        // pem chain of intermediate CA
            $table->dateTime('expires');    // datetime for expiration time
            $table->string('status');        // status of the signing request
            $table->timestamps();
            $table->softDeletes();            // keep deactivated certificates in the table for REVOCATION

            // 1:many account->certificates relationship
            $table->foreign('account_id')->references('id')->on('ca_accounts');
        });
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

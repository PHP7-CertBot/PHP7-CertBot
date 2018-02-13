<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateMonitorCertificatesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('monitor_certificates', function (Blueprint $table) {
            $table->increments('id');       // primary key to track all our acme authorizations
            $table->text('servername');     // TLS SNI to identify serverName certificate we want
            $table->text('ip');             // IP(v4) address we got back from DNS query
            $table->integer('port')         // TCP port number we connected to (usually 443)
                  ->unsigned();
            $table->text('cn');             // Certificate common name
            $table->json('san');            // Certificate subject alternative names
            $table->text('issuer');         // Issuer of the certificate
            $table->dateTime('issued_at');  // When it was issued
            $table->dateTime('expires_at'); // When it expires
            $table->longtext('cert');       // X509v3 certificate contents
            $table->timestamps();           // create/update timestamping
            $table->softDeletes();          // dont throw anything away
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop('monitor_certificates');
    }
}

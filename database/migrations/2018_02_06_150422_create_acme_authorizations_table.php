<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateAcmeAuthorizationsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('acme_authorizations', function (Blueprint $table) {
            $table->increments('id');      // primary key to track all our acme authorizations
            $table->integer('account_id')  // linkage to account id owning them
                  ->unsigned();
            $table->string('identifier');  // this is likely always going to be a DNS name
            $table->string('status');      // enum values like new, pending, valid
            $table->dateTime('expires');   // usually authz expire after 31 days
            $table->json('challenge');     // JSON array of challenge information
            $table->timestamps();          // create/update timestamping
            $table->softDeletes();         // dont throw anything away

            $table->foreign('account_id')  // add the foreign key linkage to acme account
                  ->references('id')
                  ->on('acme_accounts');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop('acme_authorizations');
    }
}

<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class UpdateAccountsForAcmev2Orders extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('acme_accounts', function (Blueprint $table) {
            $table->string('acme_account_id')->after('registration');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('acme_accounts', function (Blueprint $table) {
            $table->dropColumn('acme_account_id');
        });
    }
}

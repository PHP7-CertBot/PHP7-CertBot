<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AddAcmeAccountAuthProviderAccountField extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('acme_accounts', function (Blueprint $table) {
            $table->string('authaccount', 50)->after('authprovider')->nullable();
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
            $table->dropColumn('authaccount');
        });
    }
}

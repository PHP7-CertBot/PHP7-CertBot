<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class DropAccountIDFromAuthz extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        //throw new \Exception('DELETE everything out of acme_authorizations before running this migration!');
        DB::statement('delete from acme_authorizations');
        Schema::table('acme_orders', function (Blueprint $table) {
            $table->dropColumn('account_id');
        });

        Schema::table('acme_authorizations', function (Blueprint $table) {
            $table->dropColumn('account_id');
            $table->integer('order_id')
                ->after('id')
                ->unsigned();
            $table->index('order_id');
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

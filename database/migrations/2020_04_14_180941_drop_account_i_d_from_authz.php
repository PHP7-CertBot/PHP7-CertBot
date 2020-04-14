<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class DropAccountIDFromAuthz extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        throw new \Exception('DELETE everything out of acme_authorizations before running this migration!');

        Schema::table('acme_orders', function (Blueprint $table) {
            $table->dropIndex('acme_orders_account_id_foreign');
            $table->dropColumn('account_id');
            $table->foreign('certificate_id')->references('id')->on('acme_certificates');
        });

        Schema::table('acme_authorizations', function (Blueprint $table) {
            $table->dropForeign('acme_authorizations_account_id_foreign');
            $table->dropIndex('acme_authorizations_account_id_foreign');
            $table->dropColumn('account_id');
            $table->integer('order_id')
                ->after('id')
                ->unsigned();
            $table->index('order_id');
            $table->foreign('order_id')->references('id')->on('acme_orders');
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

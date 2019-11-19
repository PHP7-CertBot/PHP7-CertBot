<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class AddScannedAtToMonitorCertificate extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('monitor_certificates', function (Blueprint $table) {
            $table->dateTime('scanned_at')->after('created_at')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('monitor_certificates', function (Blueprint $table) {
            $table->dropColumn('scanned_at');
        });
    }
}

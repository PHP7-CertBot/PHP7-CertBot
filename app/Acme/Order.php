<?php

/**
 * CertBot Acme Client & Certificate Authority Manager.
 *
 * PHP version 7
 *
 * Manage and distribute certificates using a Laravel 5.2 RESTful JSON API
 *
 * @category  default
 * @author    Metaclassing <Metaclassing@SecureObscure.com>
 * @copyright 2015-2018 @authors
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace App\Acme;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Order extends Model implements \OwenIt\Auditing\Contracts\Auditable
{
    use SoftDeletes;
    use \OwenIt\Auditing\Auditable;

    protected $table = 'acme_orders';
    protected $fillable = ['account_id', 'certificate_id', 'status', 'expires', 'notBefore', 'notAfter', 'error', 'finalize', 'certificate'];
    protected $casts = [
        'identifiers'       => 'array',
        'authorizations'    => 'array',
        'error'             => 'array',
    ];
}

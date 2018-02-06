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

use OwenIt\Auditing\Auditable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Authorization extends Model
{
    use SoftDeletes;
    use Auditable;
    protected $table = 'acme_authorizations';
    protected $fillable = ['account_id', 'identifier'];
    protected $casts = [
        'challenge' => 'array',
    ];

    private myAccount;

    // Get the ACME account instance this certificate belongs to
    public function account($account = null)
    {
        // IF we are passed an account instance, use that specific instance
        if ($account) {
            $this->myAccount = $account;
        }
        // IF we dont have a specific instance of our parent account, get one
        if (!$this->myAccount) {
            $this->myAccount = $this->belongsTo(Account::class);
        }
        // Using a consistent instance of our account is important
        // BECAUSE IT OWNS THE ACME CLIENT INSTANCE WITH NONCE!
        return $this->myAccount;
    }

    public function getAcmeChallenge($subject)
    {
        $this->challenge = $this->account()->getAcmeChallenge($this->identifier);
    }

}

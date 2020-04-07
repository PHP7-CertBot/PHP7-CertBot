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

class Authorization extends Model implements \OwenIt\Auditing\Contracts\Auditable
{
    use SoftDeletes;
    use \OwenIt\Auditing\Auditable;

    protected $table = 'acme_authorizations';
    protected $fillable = ['account_id', 'identifier', 'challenge', 'status', 'expires'];
    protected $casts = [
        'challenge' => 'array',
    ];

    public function getChallengeTypeFromAuthorization($type = 'dns-01')
    {
        $challenges = $this->challenge['challenges'];

        foreach($challenges as $challenge) {
            if ($challenge['type'] == $type) {
                return $challenge;
            }
        }

        // we should not be here!
        throw new \Exception('Could not identify challenge type '.$type.' in authorization id '.$this->id);
    }
}

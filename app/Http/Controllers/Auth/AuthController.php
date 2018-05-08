<?php

/**
 * ExampleAPI - Laravel API example with enterprise directory authentication.
 *
 * PHP version 7
 *
 * This auth controller is an example for creators to use and extend for
 * enterprise directory integrated single-sign-on
 *
 * @category  default
 * @author    Metaclassing <Metaclassing@SecureObscure.com>
 * @copyright 2015-2016 @authors
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace App\Http\Controllers\Auth;

use App\User;
use Validator;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
// added by 3
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\ThrottlesLogins;

class AuthController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Registration & Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users, as well as the
    | authentication of existing users. By default, this controller uses
    | a simple trait to add these behaviors. Why don't you explore it?
    |
    */

    use ThrottlesLogins;

    /**
     * Where to redirect users after login / registration.
     *
     * @var string
     */
    protected $redirectTo = '/';
    private $ldap = 0;

    /**
     * Create a new authentication controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        // Let unauthenticated users attempt to authenticate, all other functions are blocked
        $this->middleware('api', ['except' => ['authenticate']]);
    }

    // Added by 3, try to cert auth, if that fails try to post ldap username/password auth, if that fails go away.
    public function authenticate(Request $request)
    {
        $error = '';
        if (env('LDAP_AUTH')) {
            // Attempt to authenticate all users based on LDAP username and password in the request
            try {
                return $this->goodauth($this->ldapauth($request));
            } catch (\Exception $e) {
                $error .= "\tError with LDAP authentication {$e->getMessage()}\n";
            }
        }
        abort(401, "All authentication methods available have failed\n".$error);
    }

    protected function ldapauth(Request $request)
    {
        if (! $request->has('username') || ! $request->has('password')) {
            throw new \Exception('Missing username or password');
        }
        $username = $request->input('username');
        $password = $request->input('password');
        //print "Auth testing for {$username} / {$password}\n";
        $this->ldapinit();
        if (! $this->ldap->authenticate($username, $password)) {
            throw new \Exception('LDAP authentication failure');
        }
        // get the username and DN and return them in the data array
        $ldapuser = $this->ldap->user()->info($username, ['*'])[0];

        return [
                'name'     => $ldapuser['cn'][0],
                'upn'      => $ldapuser['userprincipalname'][0],
                ];
    }

    // This is called when any good authentication path succeeds, and creates a user in our table if they have not been seen before
    protected function goodauth(array $data)
    {
        ////////////////////////////////////////
        // LDAP authentication is DEPRECATED! //
        ////////////////////////////////////////

        // Starting on 5.5 upgrade, no new users can be created by LDAP
        $user = User::where('userPrincipalName', $data['upn'])->first();
        if (! $user) {
            throw new \Exception('No existing user found with user principal name '.$data['upn'].' please authenticate with OAUTH via microsoft azure ad');
        }

        // Starting in 5.5 we use a new JWT generator fromUser rather than from bcrypt password
        try {
            // verify the credentials and create a token for the user
            if (! $token = \JWTAuth::fromUser($user)) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
        } catch (JWTException $e) {
            // something went wrong
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        // Cache the users oauth accss token mapped to their user object for stuff and things
        $key = '/oauth/tokens/'.$token;
        //\Cache::forever($key, $user);
        \Cache::put($key, $user, 1440);

        // if no errors are encountered we can return a JWT
        return response()->json(compact('token'));
    }

    protected function ldapinit()
    {
        if (! $this->ldap) {
            // Load the ldap library that pre-dates autoloaders
            require_once base_path().'/vendor/adldap/adldap/src/adLDAP.php';
            try {
                $this->ldap = new \adLDAP\adLDAP([
                                                    'base_dn'            => env('LDAP_BASEDN'),
                                                    'admin_username'     => env('LDAP_USER'),
                                                    'admin_password'     => env('LDAP_PASS'),
                                                    'domain_controllers' => [env('LDAP_HOST')],
                                                    'ad_port'            => env('LDAP_PORT'),
                                                    'account_suffix'     => '@'.env('LDAP_DOMAIN'),
                                                ]);
            } catch (\Exception $e) {
                abort("Exception: {$e->getMessage()}");
            }
        }
    }

    public function getLdapUserByName($username)
    {
        $this->ldapinit();
        // Search for the LDAP user by his username we copied from the certificates CN= field
        $ldapuser = $this->ldap->user()->info($username, ['*'])[0];
        // If they have unencoded certificate crap in the LDAP response, this will dick up JSON encoding
        if (isset($ldapuser['usercertificate']) && is_array($ldapuser['usercertificate'])) {
            //            unset($ldapuser["usercertificate"]);
            foreach ($ldapuser['usercertificate'] as $key => $value) {
                if (\Metaclassing\Utility::isBinary($value)) {
                    $asciicert = "-----BEGIN CERTIFICATE-----\n".
                                 chunk_split(base64_encode($value), 64).
                                 "-----END CERTIFICATE-----\n";
                    $x509 = new \phpseclib\File\X509();
                    $cert = $x509->loadX509($asciicert);
                    $cn = \Metaclassing\Utility::recursiveArrayFindKeyValue(
                                \Metaclassing\Utility::recursiveArrayTypeValueSearch(
                                    $x509->getDN(),
                                    'id-at-commonName'
                                ), 'printableString'
                            );
                    $issuer = \Metaclassing\Utility::recursiveArrayFindKeyValue(
                                    \Metaclassing\Utility::recursiveArrayTypeValueSearch(
                                        $x509->getIssuerDN(),
                                        'id-at-commonName'
                                    ), 'printableString'
                                );
                    $ldapuser['usercertificate'][$key] = "Bag Attributes\n"
                                                       ."\tcn=".$cn."\n"
                                                       ."\tserial=".$cert['tbsCertificate']['serialNumber']->toString()."\n"
                                                       ."\tissuer=".$issuer."\n"
                                                       ."\tissued=".$cert['tbsCertificate']['validity']['notBefore']['utcTime']."\n"
                                                       ."\texpires=".$cert['tbsCertificate']['validity']['notAfter']['utcTime']."\n"
                                                       .$asciicert;
                }
            }
        }
        // Handle any other crappy binary encoding in the response
        $ldapuser = \Metaclassing\Utility::recursiveArrayBinaryValuesToBase64($ldapuser);
        // Handle any remaining UTF8 encoded garbage before returning the user, this causes silent json_encode failures
        //$ldapuser = \Metaclassing\Utility::encodeArrayUTF8($ldapuser);
        return $ldapuser;
    }

}

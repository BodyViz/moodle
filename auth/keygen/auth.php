<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Authentication class for keygen is defined here.
 *
 * @package     auth_keygen
 * @copyright   2022 BodyViz <support@bodyviz.com>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');

const ACCOUNT_ID = "bc685b94-3d7f-4efc-99e4-85e12157d0a9";
const KEYGEN_BASE_URL = "https://api.keygen.sh/v1/accounts/";
const CONTENT_PRODUCT = "af03c676-7e96-4ee4-9cd7-0696960578d0";

// For further information about authentication plugins please read
// https://docs.moodle.org/dev/Authentication_plugins.
//
// The base class auth_plugin_base is located at /lib/authlib.php.
// Override functions as needed.

class Token
{
    public $id;
    public $token;
    public $userID;
    public $expires;
}

class User
{
    public $id;
    public $firstName;
    public $lastName;
    public $fullName;
    public $email;
    public $institution;
}

class License
{
    public $id;
    public $key;
    public $expires;
}

/**
 * Authentication class for keygen.
 */
class auth_plugin_keygen extends auth_plugin_base {

    /**
     * Set the properties of the instance.
     */
    public function __construct() {
        $this->authtype = 'keygen';
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username.
     * @param string $password The password.
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password): bool
    {
//        global $CFG, $DB;

        try {
            $token = $this->createUserToken($username, $password);
            $user = $this->getUser($token);
            $license = $this->getContentLicense($user, $token);
            if ($this->validateLicense($license, $token)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception $exception) {
            echo $exception->getCode() . ": " . $exception->getMessage();
        }
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's password.
     *
     * @return bool
     */
    public function can_change_password(): bool
    {
        return true;
    }

    /**
     * Returns true if this authentication plugin can edit the users'profile.
     *
     * @return bool
     */
    public function can_edit_profile(): bool
    {
        return true;
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    public function is_internal(): bool
    {
        return false;
    }

    /**
     * Indicates if password hashes should be stored in local moodle database.
     *
     * @return bool True means password hash stored in user table, false means flag 'not_cached' stored there instead.
     */
    public function prevent_local_passwords(): bool
    {
        return false;
    }

    /**
     * Indicates if moodle should automatically update internal user
     * records with data from external sources using the information
     * from get_userinfo() method.
     *
     * @return bool True means automatically copy data from ext to user table.
     */
    public function is_synchronised_with_external(): bool
    {
        return true;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool.
     */
    public function can_reset_password(): bool
    {
        return true;
    }

    /**
     * Returns true if plugin allows signup and user creation.
     *
     * @return bool
     */
    public function can_signup(): bool
    {
        return false;
    }

    /**
     * Returns true if plugin allows confirming of new users.
     *
     * @return bool
     */
    public function can_confirm(): bool
    {
        return false;
    }

    /**
     * Returns whether or not this authentication plugin can be manually set
     * for users, for example, when bulk uploading users.
     *
     * This should be overriden by authentication plugins where setting the
     * authentication method manually is allowed.
     *
     * @return bool
     */
    public function can_be_manually_set(): bool
    {
        return false;
    }

    /**
     * @throws Exception
     */
    protected function createUserToken(string $email, string $password): Token
    {
        $url = KEYGEN_BASE_URL . ACCOUNT_ID . "/tokens";

        $headers = array(
            "Accept: application/vnd.api+json"
        );

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_USERPWD, "$email:$password");
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        $resp = curl_exec($curl);

        $responseCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        if ($responseCode == 201) {
            $jsonData = json_decode($resp);
            $token = new Token();
            $token->id = $jsonData->data->id;
            $token->token = $jsonData->data->attributes->token;
            $token->userID = $jsonData->data->relationships->bearer->data->id;
            $token->expires = $jsonData->data->attributes->expiry;
            return $token;
        } else {
            throw new Exception($resp, $responseCode);
        }
    }


    /**
     * @throws Exception
     */
    protected function getUser(Token $token): User
    {
        $url = KEYGEN_BASE_URL . ACCOUNT_ID . "/users/" . $token->userID;

        $headers = array(
            "Accept: application/vnd.api+json",
            "Authorization: Bearer " . $token->token
        );

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        $resp = curl_exec($curl);

        $responseCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        if ($responseCode == 200) {
            $jsonData = json_decode($resp);
            $user = new User();
            $user->id = $jsonData->data->id;
            $user->firstName = $jsonData->data->attributes->firstName;
            $user->lastName = $jsonData->data->attributes->lastName;
            $user->fullName = $jsonData->data->attributes->fullName;
            $user->email = $jsonData->data->attributes->email;
            $user->institution = $jsonData->data->attributes->metadata->institution;
            return $user;
        } else {
            throw new Exception($resp, $responseCode);
        }
    }

    /**
     * @throws Exception
     */
    protected function getContentLicense(User $user, Token $userToken): License
    {
        $url = KEYGEN_BASE_URL . ACCOUNT_ID . "/licenses/?user=" . $user->id . "&product=" . CONTENT_PRODUCT;

        $headers = array(
            "Accept: application/vnd.api+json",
            "Authorization: Bearer " . $userToken->token
        );

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        $resp = curl_exec($curl);

        $responseCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        if ($responseCode == 200) {
            $jsonData = json_decode($resp);
            $license = new License();
            $firstLicense = $jsonData->data[0];
            $license->id = $firstLicense->id;
            $license->key = $firstLicense->attributes->key;
            $license->expires = $firstLicense->attributes->expiry;
            return $license;
        } else {
            throw new Exception($resp, $responseCode);
        }
    }

    /**
     * @throws Exception
     */
    protected function validateLicense(License $license, Token $token): bool
    {
        $url = KEYGEN_BASE_URL . ACCOUNT_ID . "/licenses/" . $license->id . "/actions/validate";

        $headers = array(
            "Accept: application/vnd.api+json",
            "Authorization: Bearer " . $token->token
        );

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        $resp = curl_exec($curl);

        $responseCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        if ($responseCode == 200) {
            $jsonData = json_decode($resp);
            return $jsonData->meta->valid;
        } else {
            throw new Exception($resp, $responseCode);
        }
    }
}

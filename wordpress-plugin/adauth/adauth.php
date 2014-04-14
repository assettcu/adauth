<?php
/*
Plugin Name: AD Authentication
Plugin URI: https://github.com/assettcu/adauth
Description: Authenticate users with their AD username and password.
Version: 1.5
Author: Ryan Carney-Mogan
Author URI: http://assett.colorado.edu/contact/staff-directory/application-development/
License:  GNU General Public License
*/

/**
 * AD Authenticate Class
 * 
 * This class uses the ADAuth Class in order to bind, authenticate, assign permissions,
 * and add users to the WordPress database.
 * 
 * NOTE: Attempts to authenticate users through the AD are logged with the service. This includes
 * attempts at incorrect passwords. If a user attempts to login 5 times with bad passwords, the user
 * will be locked out of their Identikey account for the set period of time (10 minutes). This means
 * they cannot login to MyCUInfo or other CU services until their account is unlocked (either by
 * time expiring or an administrator unlocking the account).
 * 
 */
class ADAuthenticate
{
    # Wordpress permissions:
    #   10  => Administrator
    #   7   => Editor
    #   3   => Author
    #   2   => Contributor
    #   1   => Subscriber
    private $valid_groups = array(      # The valid AD Groups with associated permission levels
        "ASSETT-Programming"=>10,
        "ASSETT-Admins"=>10,
        "ASSETT-TTAs"=>7,
        "ASSETT-Admins"=>7,
        "ASSETT-Design"=>7,
        "ASSETT-Core"=>3,
        "ASSETT-Staff"=>3,
        "ASSETT-TLCs"=>3,
    );
    
    /**
     * Constructor
     * 
     * Check to make sure there's LDAP support, then add this to the authentication hook.
     */
	public function __construct()
	{
		# Do we have LDAP support?
		if (function_exists('ldap_connect')) {
			add_filter('authenticate', array(&$this, 'adauthenticate'), 10, 3);
		}
	}

    /**
     * My Custom Error Shake
     * 
     * I don't think this works, but left here in case we want to implement this in the future.
     * 
     * @param   (array)     $shake_codes    Array of current shake codes wordpress has
     * @return  (array)                     Return the shake codes with our code appended
     */
	public function my_custom_error_shake( $shake_codes ){
		$shake_codes[] = 'denied';
		return $shake_codes;
	}

    /**
     * AD Authenticate
     * 
     * The main function of this class. This will authenticate a username and password
     * passed in from the login form on wordpress. If the user is not found in the database
     * but has authenticated successfully then they will be automatically added.
     * 
     * If the user is a first-time user, and they are just being added to the database
     * they are checked to see if they belong to specific groups in the "valid_groups"
     * variable and assigned the associated permissions.
     * 
     * @param   (object)    $user       The User Object
     * @param   (string)    $username   The username from the form
     * @param   (string)    $password   The password from the form
     * @return  (object)                Return the User Object
     */
	public function adauthenticate($user,$username,$password) {
		global $wpdb;
		
        # Pull user information from database
		$user = get_userdatabylogin( $username );
		
        # Set Authen flag
		$authenticated = false;
        
        # Pull in our AD Auth class and instantiate new session
		require_once "class.adauth.php";
		$adauth = new ADAuth("adcontroller");
		
		# Weird glitch in the matrix
		if($username == "" or $password == "") {
			return false;
		}
		
        # Check Authentication!
		if($adauth->authenticate($username,$password)) {
		    
            # If user does not exist in database BUT authenticated with the AD, let's add them
			if($user===false) {
				$info = $adauth->lookup_user();
				
                # Set flags and permission levels to default
				$flag = false;
				$current_level = 0;
				
                # Loop through valid groups to assign an appropriate permission level
				foreach($this->valid_groups as $group=>$permlevel) {
					if($adauth->is_member($group)) {
						$flag = true;
						$current_level = ($permlevel > $current_level) ? $permlevel : $current_level;
					}
				}
                
				# User is an ASSETT Staff member, add them to the database and return new user
				if($flag) {
				    
				    # Grab the user's name information from the LDAP lookup
					$firstname = @$info[0]["givenname"][0];
					$lastname = @$info[0]["sn"][0];
					
                    # Set associated numeric role with detailed role
					switch($current_level) {
						case 10: $role = "administrator"; break;
						case 7:  $role = "editor"; break;
						case 3:  $role = "author"; break;
                        case 2:  $role = "contributor"; break;
						default: $role = "subscriber"; break;
					}
                    
                    # Rand password for the password field (cannot be blank)
					$password = md5($this->gen_rand_password());
                    
					# If no email found, use identikey@colorado.edu
					if(!isset($info[0]["mail"][0])) {
						$info[0]["mail"][0] = $username."@colorado.edu";
					}
					
                    # Load up user information to be stored
					$userinfo = array(
						"user_pass"		=> $password,
						"user_login"	=> $username,
						"user_nicename"	=> $username,
						"user_email"	=> @$info[0]["mail"][0],
						"display_name"	=> @$info[0]["display_name"][0],
						"nickname"		=> $username,
						"first_name"	=> $firstname,
						"last_name"		=> $lastname,
						"description"	=> "Auto added by AD Auth",
						"role"			=> $role,
					);
                    # Store new user and pull their information to be returned
					$userid = wp_insert_user( $userinfo );
					$user = new WP_User($user->ID);
					
                    # We're done here, return user
					return $user;
				} else {
					return $user;
				}
			}
		}
        # There was an issue authenticating, usually incorrect password
		else {
			$user = new WP_Error( 'denied', __("<strong>ERROR</strong>: We could not authenticate you with the Active Directory.") );
			add_filter('shake_error_codes', array(@$this,'my_custom_error_shake'));
			return false;
		}
		
		return $user;
	}
	
    /**
     * Generate Random Password
     * 
     * Generates a random password with a given length. Used to fill the "password" field
     * for when we add users automatically. If the password field is left blank in the
     * database a user can also log in with a blank password :-O
     * 
     * @param   (integer)   $length     The length of the random string
     * @return  (string)                The random password string
     */
	private function gen_rand_password($length = 32)
	{
		$salt = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%*+";
		$len = strlen($salt);
		$makepass = '';
		mt_srand(10000000 * (double) microtime());

		for ($i = 0; $i < $length; $i ++) {
			$makepass .= $salt[mt_rand(0, $len -1)];
		}

		return $makepass;
	}
	
}

# Load up plugin
new ADAuthenticate;

?>
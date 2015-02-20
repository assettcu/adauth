<?php
/**
 *  ADAuth Class
 * 
 *  This class allows connections to the University of Colorado Active Directory domains.
 *  The configuration is built into the pre-defined variables for this class.
 * 
 *  Copyright 2014  Ryan Carney-Mogan  (email : Ryan.Carney-Mogan@colorado.edu)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2, as 
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 */

class ADAuth {
	
	public $ldap_conn;														# Default connection
	public $ldap_ad_host 		= 'ldaps://dc11.ad.colorado.edu/';	# Active Directory Controller
	public $ldap_directory_host 	= 'ldaps://directory.colorado.edu/';	# Alternate Directory Controller
	public $ldap_type 		= "";					# Which directory controller to use
	public $ldap_port 		= 636;					# SSL port for connecting
	public $ldap_user_prefix 	= 'AD\\';				# LDAP prefix
	public $ldap_connected		= false;				# Is connected?
	public $ldap_authenticated	= false;				# Is authenticated?
	public $error                   = "";                                   # Error message
	public $errno                   = 0;                                    # LDAP associated error number
	
	/**
	* Constructor
	* 
	* Sets which directory to connect with, then attempts to connect (anonymously).
	* 
	* @param   (string)    $type   Which directory to connect with (dc11 or directory)
	*/
	public function __construct($type="directory") 
	{
		$this->ldap_type = $type;
		$this->connect();
	}
	
	/**
	* Connect
	* 
	* Connects with the Active Directory Controller.
	*/
	public function connect()
	{
		try {
			# Connect to the appropriate directory controller
			if($this->ldap_type=="directory") {
				$this->ldap_conn = ldap_connect( $this->ldap_directory_host, $this->ldap_port );
			}
			else {
	                	$this->ldap_conn = ldap_connect( $this->ldap_ad_host, $this->ldap_port );
			}
			if (!$this->ldap_conn) {
				throw new Exception(ldap_error($this->ldap_conn));
			}
			ldap_set_option( $this->ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3 );  # Set the LDAP Protocol used by your AD service
			ldap_set_option( $this->ldap_conn, LDAP_OPT_REFERRALS, 0 );         # Necessary to do anything in CU's directory
	            
	            $this->ldap_connected = true;
		}
		catch( Exception $e ) {
			$this->error = "Could not connect to active directory controller:\n".$e->getMessage();
        	}
	}
	
	/**
	* Change Controller
	* 
	* Allows a user to switch between AD Controllers (to pull different information, to authenticate, or other things).
	* It will disconnect from the currently connected directory to switch to the other.
	* 
	* @param   (string)    $controller   Which directory to swtich to (dc11 or directory)
	*/
	public function change_controller($controller)
	{
		$this->ldap_type = $controller;
		$this->close_connection();
		$this->connect();
	}
	
	/**
	* Close Connection
	* 
	* Closes the currently active LDAP connection and resets the authen variable.
	*/
	public function close_connection()
	{
		if($this->ldap_connected) {
			ldap_close($this->ldap_conn);
			$this->ldap_connected = false;
			$this->ldap_authenticated = false;
		}
	}
	
	/**
	* Bind User
	* 
	* Binds the user with the current connection. This is the main authentication function.
	* Binding a user will authenticate the user, but also allow the user to look up information
	* in the DC11 AD Controller which has different information than in the "Directory" controller.
	*/
	public function bind_user($username,$password)
	{
		try {
			$this->username = $username;
			# Bind the user credentials to the connection (this checks to see if the user crendentials are valid or not)
			$authentication_success = ldap_bind( $this->ldap_conn, $this->ldap_user_prefix . $username, $password );
			$this->ldap_authenticated = $authentication_success;
		}
		catch(Exception $e) {
			$this->errno = ldap_errno($this->ldap_conn);
			$this->error = "Error binding user with active directory connection.\n".$e->getMessage();
		}
	}

	/**
	* Bind Anonymously
	* 
	* Binds anonymously with the current connection. This function is important for looking up user
	* information without having to have a user login. The "directory" AD Controller is the only
	* controller currently that allows anonymous bind and lookup.
	*/
	public function bind_anon()
	{
		try {
			# Attempts to connect to the AD controller without a username/password (anonymous connection)
			$authentication_success = ldap_bind( $this->ldap_conn );
			$this->ldap_authenticated = $authentication_success;
		}
		catch(Exception $e) {
			$this->errno = ldap_errno($this->ldap_conn);
			$this->error = "Error binding anonymously with active directory connection.\n".$e->getMessage();
		}
	}
	
	/**
	* Authenticate
	* 
	* Takes a username/password combination and attempts to bind them to the LDAP connection.
	* 
	* @param   (string)    $username       The username to authenticate
	* @param   (string)    $password       The password to authenticate
	* @return  (bool)                      Whether the authentication was successful or not
	*/
	public function authenticate($username,$password)
	{
		# Reset the flag
		$this->ldap_authenticated = false;
		
		# Authenticate
		$this->bind_user($username,$password);
		
		return $this->ldap_authenticated;
	}

	/**
	* Lookup User
	* 
	* Attempts to lookup a user in the currently connected controller by their username.
	* There are different lookup strings for the different controllers (due to how the information
	* is store in each Active Directory).
	* 
	* For instance, the username is stored as the "UID" in the "Directory" controller and "CN" in
	* the DC11 controller.
	* 
	* @param   (string)    $username       Username to lookup
	* @return  (array)                     Returns an array of information from the lookup
	*/
	public function lookup_user($username="")
	{
		if($username=="" and (!isset($this->username) or $this->username == "")) {
			return false;
		} else if($username=="") {
			$username = $this->username;
		}
		
		if($this->ldap_type == "directory") {
			$results = ldap_search( $this->ldap_conn, 'OU=people,DC=colorado,DC=edu', "(uid=$username)" );
		} else {
			$results = ldap_search( $this->ldap_conn, 'DC=ad,DC=colorado,DC=edu', "(CN=$username)" );
		}
		
		$info = ldap_get_entries( $this->ldap_conn, $results );
		return $info;
	}

	/**
	* Lookup User By Name
	* 
	* Attempts to lookup a user in the currently connected controller by their full name.
	* There are different lookup strings for the different controllers (due to how the information
	* is store in each Active Directory).
	* 
	* @param   (string)    $name           Full name to lookup
	* @return  (array)                     Returns an array of information from the lookup
	*/
	public function lookup_user_byname($name)
	{
		try {
			# Do a bunch of checking first
			if($this->ldap_type != "directory") {
				throw new Exception("LDAP connection must be the \"Directory\"");
			}
			else if($name == "") {
				throw new Exception("Name parameter cannot be empty.");
			}
			else if($this->ldap_connected === false) {
				throw new Exception("The ldap connection is not active.");
			}
			
			# Look up user by name
			$results = ldap_search($this->ldap_conn, 'OU=people,DC=colorado,DC=edu', "(cn=$name)");
			if(!$results) {
				return false;
			}
			
			# Retrieve entries and return
			$info = ldap_get_entries($this->ldap_conn, $results);
			return $info;
		}
		catch(Exception $e) {
			$this->error = "Error looking up user by name.\n".$e->getMessage();
			return false;
		}
	}
	

	/**
	* Lookup User By ID
	* 
	* Same as lookup_user_byname() except by their UUID.
	* 
	* @param   (string)    $name           Full name to lookup
	* @return  (array)                     Returns an array of information from the lookup
	*/
	public function lookup_user_byid($uuid)
	{
		try {
			# Do a bunch of checking first
			if($this->ldap_type != "directory") {
				throw new Exception("LDAP connection must be the \"Directory\"");
			}
			else if($uuid == "") {
				throw new Exception("UUID parameter cannot be empty.");
			}
			else if($this->ldap_connected === false) {
				throw new Exception("The ldap connection is not active.");
			}
			
			# Look up user by UUID
			$results = ldap_search( $this->ldap_conn, 'OU=people,DC=colorado,DC=edu', "(cuedupersonuuid=$uuid)" );
			if(!$results) {
				return false;
			}
			
			# Retrieve entries and return
			$info = ldap_get_entries( $this->ldap_conn, $results );
			return $info;
		}
		catch(Exception $e) {
			$this->error = "Error looking up user by name.\n".$e->getMessage();
			return false;
		}
	}
	
	/**
	* Lookup User By ID
	* 
	* Same as lookup_user_byname() except by their UUID.
	* 
	* @param   (string)    $name           Full name to lookup
	* @return  (array)                     Returns an array of information from the lookup
	*/
	public function lookup_user_relname($name)
	{
		if($this->ldap_type != "directory" or $name == "") {
			return false;
		}
	
		$results = @ldap_search( $this->ldap_conn, "OU=people,DC=colorado,DC=edu", "(displayname=$name *)");
		if(!$results) {
			return false;
		}
		
		$info = ldap_get_entries( $this->ldap_conn, $results );
		return $info;
	
	}
	
	/**
	* Get Memberships
	* 
	* Get the user's groups and return as a formatted array.
	* 
	* @return  (array)     Array of groups the user belongs to
	*/
	public function get_memberships()
	{
		# We need the user's information before we parse    
		if(!isset($this->userinfo)) {
			$this->userinfo = $this->lookup_user();
		}
		if(empty($this->userinfo) or $this->userinfo === false) {
			return false;
		}
		
		# Grab the groups portion of the LDAP data
		$memberof = $this->userinfo[0]["memberof"];
		
		# Parse through each group and put into an array
		$groups = array();
		for( $a=0; $a<$memberof["count"]; $a++) {
			list($membership,$ou) 	= explode(",",$memberof[$a],3);
			$membership 		= str_replace("CN=","",$membership);
			$ou 			= str_replace("OU=","",$ou);
			$groups[] 		= array("cn"=>$membership,"ou"=>$ou);
		}
		
		return $groups;
	}

	/**
	* Is Member
	* 
	* Does the user have a specific AD group?
	* For example, a member of the Communication department should belong
	* to the COMM-Users group. If I bind a user from the COMM department and
	* did is_member("COMM-Users") it should return true.
	* 
	* @param   (string)    $club   Which group to lookup
	* @return  (bool)              Returns whether that user belongs to the group or not
	*/
	public function is_member($club) 
	{
		$groups = $this->get_memberships();
		if(!empty($groups)){
			foreach($groups as $group) {
				if($group["cn"]==$club) return true;
			}
		}
		return false;
	}
	
	/**
	* Is Member Regular Expression
	* 
	* Same as the "is_member()" function above, except it looks up groups
	* by a regular expression passed in as the parameter. Good for finding groups with
	* approximate names such as "????-admins".
	* 
	* @param   (string)    $club_regex     Which group to lookup as a regular expression
	* @return  (bool)                      Returns whether that user belongs to the group or not
	*/
	public function is_member_regex($club_regex)
	{
		$groups = $this->get_memberships();
		if(!empty($groups)) {
			foreach($groups as $group) {
				if($preg_match("/".$club_regex."/",$group)) return true;
			}
		}
		return false;
	}
}
?>

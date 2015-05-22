# UserCredential
This package can implement password authentication policies. It can perform several types of check to evaluate if user passwords and authentication procedures comply with security recommendations

#INTRODUCTION
The user credentials service will provide pluggable service that enables one to validate 
passwords and policyfrom any source. It will contain a comprehensive list of validation
requirements as per the CERT guidlines.

#LICENSE
BSD-3-CLAUSE

#BACKGROUND

PHP Applications rarely implement complex Password policy out of the box. This Service aims to accompmlish two goals

1) Implement best policy in password encryption and verification (At the moment being PHP's bcrypt library)
2) Implement best policy with regards to Authentication and Password policy by using OWASPS Secure Coding Practices
   (https://www.owasp.org/index.php/OWASP_Secure_Coding_Practices_-_Quick_Reference_Guide)
3) Provide easy way to integrate password policy to your application. When you use the service out of the box
   without custom configuration, it provides the following
      - Temporary lock out account after 4 successive illegal login attempts for 10 minutes
	  - Indefinately lock out account on 5th successive illegal login attempt
	  - User cannot repeat 5 last passwords
	  - User passwords expire after 45 days
	  - Enforce password change when a password is not of the required entropy
	  - Minimum password length required of 8 characters
	  - Minimum password entropy is 2 capital case alphabet characters, 2 lower case alphabet characters, 1 numeric character and 1 special character
4) Provide a consistent interface for authentication and policy processes regardless of the backend used

#FUNCTIONALITY PROVIDED

All authentication controls should fail securely: The Service is not intrusive. A UserProfile is provided to the service and it does not intervene unless it encounters an issue with the authentication or policy at which point it throws a UserCredentialException, which should then be handled

Enforce password complexity requirements established by policy or regulation. Authentication credentials should be sufficient to withstand attacks that are typical of the threats in the deployed environment. (e.g., requiring the use of alphabetic as well as numeric and/or special characters): The service has a method for implementing user defined policy based on length and complexity. However, it does not let one set a Weak policy as it compares the User defined policy to the built in base policy, and if the User defined policy is weak e.g. If Password length is 5 characters in user defined policy, it will fall back to the base (8 characters as per OWASP)

Enforce password length requirements established by policy or regulation. Eight characters is commonly used, but 16 is better or consider the use of multi-word pass phrases: See previous point

Enforce account disabling after an established number of invalid login attempts (e.g., five attempts is common). The account must be disabled for a period of time sufficient to discourage brute force guessing of credentials, but not so long as to allow for a denial-of-service attack to be performed: The service locks the account temporarily (10 minutes in base policy) for repeated attempts. After 10 minutes, the user will successfully log in with the correct password. However, if at any time after this the User provides another wrong password, the service locks the account indefinitely which will require admin intervention to unlock

Enforce the changing of temporary passwords on the next use: The service will recommend/enforce password change on next attempted login when using a weak password

Prevent password re-use: The service can support this. By default the last 5 passwords are not allowed to be repeated. User defined policy can increase this. We have seen up to 12 previous passwords being used in some environments.

Enforce password changes based on requirements established in policy or regulation. Critical systems may require more frequent changes. The time between resets must be administratively controlled: The service has a default expiry period for passwords of 45 days. A stronger User Defined Policy (e.g. 30 days) can be set using the User defined policy methods.

Use Multi-Factor Authentication for highly sensitive or high value transactional accounts. The service implements an Interface that can allow for Multi-Factor authentication. We are currently integrating 2 factor authentication using TOTPâ€™s MultiOTP library

#USAGE
1) Requirements
 - PHP >= 5.4
 - Composer
 - If your PHP version is 5.4, you will need to ensure you install the password_compat function. This
   is implemented by Bcrypt library in PHP 5.5 and later. https://github.com/ircmaxell/password_compat
  
2) Installation
 - Run composer install / update and include the UserCredential package in your Autoloader
 - Include the file Config/NamedConstant.php in your application as well
 
4) Named Constants (Provided in NamedConstant.php)
	//UserCredential constants for user authentication
	const USERCREDENTIAL_ACCOUNTSTATE_LOGGEDOUT   = 1;
	const USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN    = 2;
	const USERCREDENTIAL_ACCOUNTSTATE_LOCKED1     = 3;
	const USERCREDENTIAL_ACCOUNTSTATE_LOCKED2     = 4;
	const USERCREDENTIAL_ACCOUNTSTATE_RESET       = 5;
	const USERCREDENTIAL_ACCOUNTSTATE_SUSPENDED   = 6;
	const USERCREDENTIAL_ACCOUNTSTATE_AUTHFAILED  = 7;
	const USERCREDENTIAL_ACCOUNTSTATE_WEAKPASSWD  = 8;

	//UserCredential constants for account policy actions
	const USERCREDENTIAL_ACCOUNTPOLICY_VALID         = 1;
	const USERCREDENTIAL_ACCOUNTPOLICY_EXPIRED       = 2;
	const USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT1 = 3;
	const USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT2 = 4;
	const USERCREDENTIAL_ACCOUNTPOLICY_REPEATERROR   = 5;
	const USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD    = 6;
	const USERCREDENTIAL_ACCOUNTPOLICY_NAMEINPASSWD  = 7;


3) Build User Profile
 - This service is decoupled from backend store of user and auth info. It will need an array of the userProfile,
   which you should build and provide to the Service.

 - A test userprofile is as follows
 
						array(
						  "username"=>"c.ogana",
                          "password"=>"m&$1eLe6Ke()",					//Password provided by user when loggin in, else null if youre running this in session and not log in
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"bcrypt",
                          "passhist"=>array(							//These should be already stored as encrypted in your backend store :)
                            \password_hash('abc', \PASSWORD_DEFAULT),
                            \password_hash('def', \PASSWORD_DEFAULT),
                            \password_hash('ghi', \PASSWORD_DEFAULT),
                            \password_hash('jkl', \PASSWORD_DEFAULT),
                            \password_hash('mno', \PASSWORD_DEFAULT),
                            \password_hash('pqr', \PASSWORD_DEFAULT),
                            \password_hash('stu', \PASSWORD_DEFAULT),
                            \password_hash('vwx', \PASSWORD_DEFAULT),
                            \password_hash('xyz', \PASSWORD_DEFAULT)
                          ), //in reality, these are bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' 		   => 0,
                              'password_last_changed_datetime' => new \DateTime('2014-05-04'),
                              'last_login_attempt_datetime'    => new \DateTime('2014-05-16 23:45:10')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);  //See below for description of named constants

4) Usage During Logging In
	//Autoload the Service
	//Build user Profile First (see sample above)
	
	//Note below the main methods are validateEntropy()and validatePolicy()
	
	$userCredentialService = new UserCredentialManager($userProfile);
	
	try {
		$usercredentialService->validateEntropy($userProfile);
		$checkPolicy = true;
	} catch (UserCredentialException $enException) {
		$enExceptionId = $enException->getCode();
		$userStateUpdated = true;
		$checkPolicy = false;
		//Handle the Exception...
	}

	if ($checkPolicy) {
		try {
			$usercredentialService->validatePolicy($userProfile);
		} catch (UserCredentialException $plcyException) {
			//Handle the Exception
		}
	}
	
	//Yay, we made it. Do something Amazing ... :)


5) Usage During Sessions
 - Usage during sessions is as above, except you cannot use validateEntropy() only validatePolicy() e.g on accessing a resource it may calculate
   that the 45 days have elapsed and throw exception requiring password change

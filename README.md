# PHP USERCREDENTIALS

This package can implement password authentication and policy management. It can perform several types of check to evaluate if user passwords and authentication procedures comply with security recommendations

## Description

The PHP UserCredential Package is a pluggable service that enables one to validate 
passwords and policy. It validates against a set of password policies as recommended
by OWASP best practice guidelines for Web applications.

The package also provides an Interface that allows plugging in 3rd party
libraries, particularly for Multi Factor Authentication methods. To Illustrate how, we
have plugged in MultiOTP library (https://github.com/multiOTP/multiotp) for
the SMS OTP and Google Authenticator TOTP services that we have provided with this package.

## Installing

### Install application via Composer

    require "cymapgt/usercredential": "*"

## Usage

### Overview

This package is intended for PHP applications which use Password for authentication and are
required to maintain a User Credential policy of sorts. We also offer Multi Factor authentication services which utilize the MultiOTP Library.

The objectives of the Package are 

* Implement policy for password encryption and verification (At the moment being PHP's bcrypt library)

* Implement policy for authentication and password management by implementing authentication guidlines in 
  OWASP Secure Coding Practices ([https://www.owasp.org/index.php/OWASP_Secure_Coding_Practices_-_Quick_Reference_Guide](https://www.owasp.org/index.php/OWASP_Secure_Coding_Practices_-_Quick_Reference_Guide)

* Provide an easy way to integrate password policy to your application. When you use the service out of the box
   without custom configuration, it provides the following

 **(Introduced Version 1.2)** 

 - Temporary lock out account after 4 successive illegal login attempts for 10 minute

 - Indefinately lock out account on 5th successive illegal login attempt

 - User cannot repeat 5 last passwords

 - User passwords expire after 45 days

 - Enforce password change when a password is not of the required entropy

 - Minimum password length required of 8 characters

 - Minimum password entropy is 2 capital case alphabet characters, 2 lower case alphabet characters, 1 numeric character and 1 special character

 - User cannot use their Username, or their real name (or part of) in the Password string

  **(Introduced Version 1.3)** 

 - Password cannot contain more than 2 consecutive characters (e.g. *aaa*)

 - Password strength checker Class is included (Kudos to Ryan Chouinard for development of the lovely Phpass package (**rchouinard/phpass**) [https://github.com/rchouinard/phpass](https://github.com/rchouinard/phpass)), which we Forked for the strength functionality checker using NIST and Wolfram algorithms

* Provide a consistent interface for authentication and policy processes regardless of the backend store used

### Implementation of OWASP Guidlines

 * **All authentication controls should fail securely:** The Service is not intrusive. A UserProfile is provided to the service and it does not intervene unless it encounters an issue with the authentication or policy at which point it throws a UserCredentialException, which should then be handled

 * **Enforce password complexity requirements established by policy or regulation. Authentication credentials should be sufficient to withstand attacks that are typical of the threats in the deployed environment. (e.g., requiring the use of alphabetic as well as numeric and/or special characters):** The service has a method for implementing user defined policy based on length and complexity. However, it does not let one set a Weak policy as it compares the User defined policy to the built in base policy, and if the User defined policy is weak e.g. If Password length is 5 characters in user defined policy, it will fall back to the base (8 characters as per OWASP). **NB: Falling back to be introduced and is not yet implemented.**

 * **Enforce password length requirements established by policy or regulation. Eight characters is commonly used, but 16 is better or consider the use of multi-word pass phrases:** See previous point

 * **Enforce account disabling after an established number of invalid login attempts (e.g., five attempts is common). The account must be disabled for a period of time sufficient to discourage brute force guessing of credentials, but not so long as to allow for a denial-of-service attack to be performed:** The service locks the account temporarily (10 minutes in base policy) for repeated attempts. After 10 minutes, the user may successfully log in with the correct password. However, if at any time after this the User provides another wrong password, the service locks the account indefinitely which will require admin intervention to unlock

 * **Enforce the changing of temporary passwords on the next use:** The service will recommend/enforce password change on next attempted login when using a weak password

 * **Prevent password re-use:** The service can support this. By default the last 5 passwords are not allowed to be repeated. User defined policy can increase this. We have seen up to 12 previous passwords being used in some environments.

 * **Enforce password changes based on requirements established in policy or regulation. Critical systems may require more frequent changes. The time between resets must be administratively controlled:** The service has a default expiry period for passwords of 45 days. A stronger User Defined Policy (e.g. 30 days) can be set using the User defined policy methods.

 * **Use MultiFactor Authentication for highly sensitive or high value transactional accounts** The service implements an Interface that can allow for Multi-Factor authentication. 

### Using the Package

#### Named Constants

    //UserCredential constants for user authentication
    const USERCREDENTIAL_ACCOUNTSTATE_LOGGEDOUT   = 1;
    const USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN    = 2;
    const USERCREDENTIAL_ACCOUNTSTATE_LOCKED1     = 3;
    const USERCREDENTIAL_ACCOUNTSTATE_LOCKED2     = 4;
    const USERCREDENTIAL_ACCOUNTSTATE_RESET       = 5;
    const USERCREDENTIAL_ACCOUNTSTATE_SUSPENDED   = 6;
    const USERCREDENTIAL_ACCOUNTSTATE_AUTHFAILED  = 7;
    const USERCREDENTIAL_ACCOUNTSTATE_WEAKPASSWD  = 8;

    /**
     * UserCredential constants for account policy actions. These also serve as
     * exception codes during the authentication and policy check process.
     * Internal Exception codes are documented in the EXCEPTIONS.md file
     */

    const USERCREDENTIAL_ACCOUNTPOLICY_VALID         = 1;
    const USERCREDENTIAL_ACCOUNTPOLICY_EXPIRED       = 2;
    const USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT1 = 3;
    const USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT2 = 4;
    const USERCREDENTIAL_ACCOUNTPOLICY_REPEATERROR   = 5;
    const USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD    = 6;
    const USERCREDENTIAL_ACCOUNTPOLICY_NAMEINPASSWD  = 7;

    //Password strength constants
    const PHPASS_PASSWORDSTRENGTHADAPTER_NIST = 0;
    const PHPASS_PASSWORDSTRENGTHADAPTER_WOLFRAM = 1;

#### Building Your User's Profile

 * This service is decoupled from backend store of user and auth info. It will need an array of the userProfile,
   which you should build and provide to the Service.
 
#### Sample User Profile 

    array (
        "username" => "james",
        "password" => "m&$1eLe6Ke()", //Password provided by user when loggin in, else null if youre running this in session and not log in
        "fullname" => "James Rodriguez",
        "passhash" => "bcrypt",
        "passhist" => array( //These should be already stored as encrypted in your backend store and would be of required entropy :)
            \password_hash('abc', \PASSWORD_DEFAULT),
            \password_hash('def', \PASSWORD_DEFAULT),
            \password_hash('ghi', \PASSWORD_DEFAULT),
            \password_hash('jkl', \PASSWORD_DEFAULT),
            \password_hash('mno', \PASSWORD_DEFAULT),
            \password_hash('pqr', \PASSWORD_DEFAULT),
            \password_hash('stu', \PASSWORD_DEFAULT),
            \password_hash('vwx', \PASSWORD_DEFAULT),
            \password_hash('xyz', \PASSWORD_DEFAULT)
        ),
        "policyinfo"=>array(
            'failed_attempt_count' => 0,
            'password_last_changed_datetime' => new \DateTime('2014-05-04'),
            'last_login_attempt_datetime'    => new \DateTime('2014-05-16 23:45:10')
        ),
        "account_state" => \USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN
    );

#### Authenticating A User

The service comes with 3 Password Authenticating Services which you can Choose From.
A Wiki for using each of the services as well as on implementing password policy is
in the pipeline. This article here http://bit.ly/29m2aWL that explains using a DB 
as a backend store might assist with getting started on using the package.

Check the test file for these services for some documentation on their workings.

##### UserCredentialPasswordLoginService

This service does password authentication only. To use this service, you will need to
plug it in to the authentication Framework / Plugin that you are using.

##### UserCredentialSmsTokenLoginService

This service generates Tokens which are sent to the mobile number or email that is mapped
to the user. This class extends UserCredentialPasswordLoginService which performs the first
step of the authentication.

##### UserCredentialGoogleAuthLoginService

This service generates TOTP tokens which change in intervals of 30 seconds. Thus, these
can support Google Authenticator. This class extends UserCredentialPasswordLoginService
which performs the first step of the authentication.

#### Enforcing Password Policy After Authenticating

    use cymapgt\core\application\authentication\UserCredential;
    //Build user Profile First (see sample above)

    $userCredentialService = new UserCredentialManager($userProfile);

    try {
        $usercredentialService->validateEntropy();
        $usercredentialService->validateLength();
        $usercredentialService->validateConsecutiveCharacterRepeat();
        $checkPolicy = true;
    } catch (UserCredentialException $enException) {
        $enExceptionId = $enException->getCode();
        $checkPolicy = false;
        //Handle the Exception...
    }

    if ($checkPolicy) {
        try {
            $usercredentialService->validatePolicy();
        } catch (UserCredentialException $plcyException) {
            //Handle the Exception...
        }
    }

    //Yay, we made it. Do something Amazing ... :)

#### Enforcing Password Policy During Sessions

 * Usage during sessions is as above, except you cannot use validateEntropy() etc .... only validatePolicy() e.g on accessing a resource it may calculate
that the 45 days have elapsed and throw exception requiring password change

#### Verifying Password Strength with Phpass

The strength checker method is static, to allow for usage without needing instantiation of the UserCredentialManager class. Thus, it can also be used in assisting users when they are changing passwords or setting up new passwords.

    use cymapgt\core\application\authentication\UserCredential; 
        
    $passwordStrength = UserCredentialManager::passwordStrength($passwordString);
 
    //do something like show strength bar, or enforce stronger password


### Testing

PHPUnit Tests are provided with the package


### Contribute

* Email @rhossis or contact via Skype
* Fork the repository on GitHub to start making your changes to the master branch (or branch off of it).
* You will be added as author for contributions

### License

BSD 3 CLAUSE

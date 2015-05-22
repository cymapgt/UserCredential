<?php
namespace cymapgt\core\application\authentication\UserCredential\abstractclass;

use cymapgt\Exception\UserCredentialException;

/**
 * UserCredential
 * This service implements user password policy as well as facilitating
 * plugging in to log in infrastructures that utilize SSO via LDAP
 * and one time password logging in via OATH and SecureId
 *
 * @category    
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2014 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
 * 
 * The objectives of the user credential class are:
 *      - Add password entropy component – suggestion and enforcement
 *      - Add ability to choose number of simultaneous logins allowed for users
 *      - Add ability to choose user allowed login devices
 *      - Add ability to choose user allowed login IP/host
 *      - Add ability to choose user  allowed log in days
 *      - Add ability to choose user allowed log in time
 *      - Add ability to set the tenor of the user account in the system
 *      - Add ability to reset a users password
 *      - Add ability to lock users passwords for violation of system rules
 *      - Two factor authentication component
 *      - Password expiry frequency component
 *      - RSA one time password authentication component
 *      - Embed the user management module to the maker-checker module process such that if required, any creation/update of users information requires 2, 3 or N step authentication e.g. created by, modified by
 *      - Add option to email a user that a new account has been created on his/her behalf
 *      - The password hash should be at least sha256
 * 
 *      - See http://www.owasp.org/images/0/08/OWASP_SCP_Quick_Reference_Guide_v2.pdf
 */

abstract class UserCredentialAbstract
{
    private $_userProfile         = array();      //Array containing user information to use in the class
    
    private $_baseEntropySetting  = array();      //This is the default entropy setting
    private $_baseEntropyOverride = false;        //A flag to turn off base entropy enforcement
    private $_udfEntropySetting   = array();      //A variable to store the user defined entropy

    private $_basePasswordPolicy  = array();      //Base password policy maintained by UserCredential class
    private $_udfPasswordPolicy   = array();      //Udf password policy maintained by UserCredential class
	
        
    //Constructor method
    public function __construct($userProfile){
        $this->_initialize($userProfile);
    }
	
    /**
     * function initialize() - Initialize the classes default settings
     * Cyril Ogana <cogana@gmail.com> - 2013-05-13
     *
     * @param array / object  userProfile
     *
     * @access private
     */             
    private function _initialize($userProfile){
        $this->_initializeProfile($userProfile);
        $this->_initializeBaseEntropy();
        $this->_initializeBasePasswordPolicy();
    }
	
   /** 
    * function initializeProfile() - Function to initialize user profile data
    * 
    * Cyril Ogana <cogana@gmail.com> - 2013-05-13 
    *
    * @param  array / object $userProfile
    *
    * @access private
    */
    private function _initializeProfile($userProfile){
        //validate that user profile has the correct information
        if(!is_array($userProfile)
            || !isset($userProfile['username'])
            || !isset($userProfile['password'])
            || !isset($userProfile['fullname'])			
            || !isset($userProfile['passhash'])
            || !is_string($userProfile['passhash'])
            || !isset($userProfile['passhist'])
            || !is_array($userProfile['passhist'])
            || !isset($userProfile['account_state'])
            || !isset($userProfile['policyinfo'])
            || !is_array($userProfile['policyinfo'])
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('the user profile is not properly initialized');
        }
        $this->_userProfile = $userProfile;
    }

    /**
     * function initializeBaseEntropy() = Initialize to hard coded default base tntropy
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @access private
     */ 	
    private function _initializeBaseEntropy() {
        //initialize if not already initialized as array
        if(!is_array($this->_baseEntropySetting)){
                $this->_baseEntropySetting = array();
        }

        $this->_baseEntropySetting['min_pass_len'] = 8;
        $this->_baseEntropySetting['uppercase']    = array(
                                                        'toggle'  => true,
                                                        'min_len' => 2
                                                     );
        $this->_baseEntropySetting['numeric']     = array(
                                                        'toggle'  => true,
                                                        'min_len' => 1														
                                                    );
        $this->_baseEntropySetting['lowercase']   = array(
                                                        'toggle'  => true,
                                                        'min_len' => 2
                                                    );
        $this->_baseEntropySetting['special']     = array(
                                                        'toggle'  => true,
                                                        'min_len' => 1
                                                    );
        $this->_baseEntropyOverride = false;
        $this->_setUdfEntropy($this->_baseEntropySetting);
    }
    
    /**
     * function _initializeBasePasswordPolicy() = Initialize to hard coded default base policy
     * Cyril Ogana <cogana@gmail.com>
     * 2014-02-11
     *
     * @access private
     */ 	
    private function _initializeBasePasswordPolicy() {
        $this->_basePasswordPolicy['illegal_attempts_limit']           = 3;
        $this->_basePasswordPolicy['password_reset_frequency']         = 45;
        $this->_basePasswordPolicy['password_repeat_minimum']          = 5;
        $this->_basePasswordPolicy['illegal_attempts_penalty_seconds'] = 600;
        $this->_setUdfPasswordPolicy($this->_basePasswordPolicy);
    }
    
    /**
     * function getBaseEntropy() = Get the base entropy data structure
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @return array / Object
     * 
     * @access protected
     * @final
     */
    final protected function _getBaseEntropy() {
	if(isset($this->_baseEntropySetting)){
            return $this->_baseEntropySetting;
        }
    }
    
    /**
     * function getBasePasswordPolicy() = Get the base password policy
     * Cyril Ogana <cogana@gmail.com>
     * 2014-02-11
     *
     * @return array / Object
     * 
     * @access protected
     * @final
     */
    final protected function _getBasePasswordPolicy() {
	if(isset($this->_basePasswordPolicy)){
            return $this->_basePasswordPolicy;
        }
    }  

    /**
     * function setUdfEntropy() = Set the user defined entropy setting
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @param  array / object entropyObj - array or object implementing ArrayAccess
     *
     * @access protected
     * @final
     */ 
     final protected function _setUdfEntropy($entropyObj) {
        //initialize if not already initialized as array
        if(!is_array($this->_udfEntropySetting)
           || 
           (!is_object($this->_udfEntropySetting)
            &&
            $this->_udfEntropySetting instanceof \ArrayAccess)
        ){
            $this->_udfEntropySetting = array();
        }

        //validate the array / object
        if(!is_array($entropyObj)){
            if(!is_object($entropyObj)
                || !($entropyObj instanceof \ArrayAccess)
            ){
                //todo: throw exception here
                throw new UserCredentialException('The entropy object should be an array or implement ArrayAccess interface');
            }
        }

        //validate that minimum password len has the correct indices, then set it
        if(!isset($entropyObj['min_pass_len'])
            || !is_int($entropyObj['min_pass_len']) 
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('the minimum password length hasn\'t been set');
        }
        $this->_udfEntropySetting['min_pass_len'] = $entropyObj['min_pass_len'];

        //validate that uppercase snippet has correct indices, then set it
        if(!isset($entropyObj['uppercase'])
            || !is_array($entropyObj['uppercase'])
            || !isset($entropyObj['uppercase']['toggle'])
            || !is_bool($entropyObj['uppercase']['toggle'])
            || !isset($entropyObj['uppercase']['min_len'])
            || !is_int($entropyObj['uppercase']['min_len'])
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('the uppercase settings must be an array containing toggle and min upper length');
        }
        $this->_udfEntropySetting['uppercase'] = $entropyObj['uppercase'];

        //validate that lowercase snippet has correct indices, then set it
        if(!isset($entropyObj['lowercase'])
           || !is_array($entropyObj['lowercase'])
           || !isset($entropyObj['lowercase']['toggle'])
           || !is_bool($entropyObj['lowercase']['toggle'])
           || !isset($entropyObj['lowercase']['min_len'])
           || !is_int($entropyObj['lowercase']['min_len'])
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('the lowercase settings must be an array containing toggle and min lower length');
        }
        $this->_udfEntropySetting['lowercase'] = $entropyObj['lowercase'];

        //validate that numeric chars snippet has correct indices, then set it
        if(!isset($entropyObj['numeric'])
            || !is_array($entropyObj['numeric'])
            || !isset($entropyObj['numeric']['toggle'])
            || !is_bool($entropyObj['numeric']['toggle'])
            || !isset($entropyObj['numeric']['min_len'])
            || !is_int($entropyObj['numeric']['min_len'])
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('the numeric settings must be an array containing toggle and min lower length');
        }
        $this->_udfEntropySetting['numeric'] = $entropyObj['numeric'];

        //validate that special chars snippet has correct indices, then set it
        if(!isset($entropyObj['special'])
            || !is_array($entropyObj['special'])
            || !isset($entropyObj['special']['toggle'])
            || !is_bool($entropyObj['special']['toggle'])
            || !isset($entropyObj['special']['min_len'])
            || !is_int($entropyObj['special']['min_len'])
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('the uppercase settings must be an array containing toggle and min upper length');
        }
        $this->_udfEntropySetting['special'] = $entropyObj['special'];
    }
    
    /**
     * function setUdfPasswordPolicy() = Set the user defined password policy
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @param  array / object entropyObj - array or object implementing ArrayAccess
     *
     * @access protected
     * @final
     */ 
     final protected function _setUdfPasswordPolicy($entropyObj) {
        //initialize if not already initialized as array
        if(!is_array($this->_udfPasswordPolicy)
           || 
           (!is_object($this->_udfPasswordPolicy)
            &&
            $this->_udfPasswordPolicy instanceof \ArrayAccess)
        ){
            $this->_udfPasswordPolicy = array();
        }

        //validate the array / object
        if(!is_array($entropyObj)){
            if(!is_object($entropyObj)
                || !($entropyObj instanceof \ArrayAccess)
            ){
                //todo: throw exception here
                throw new UserCredentialException('The entropy object should be an array or implement ArrayAccess interface');
            }
        }

        //validate that illegal attempts limit has correct indices, then set it
        if(!isset($entropyObj['illegal_attempts_limit'])
            || !is_int($entropyObj['illegal_attempts_limit']) 
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('the illegal attempts limit hasn\'t been set');
        }
        $this->_udfPasswordPolicy['illegal_attempts_limit'] = $entropyObj['illegal_attempts_limit'];

        //validate that password reset frequency has correct indices, then set it
        if(!isset($entropyObj['password_reset_frequency'])
            || !is_int($entropyObj['password_reset_frequency']) 
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('The password reset frequency hasn\'t been set');
        }
        $this->_udfPasswordPolicy['password_reset_frequency'] = $entropyObj['password_reset_frequency'];

        //validate that passwordd repeat minimum has correct indices, then set it
        if(!isset($entropyObj['password_repeat_minimum'])
            || !is_int($entropyObj['password_repeat_minimum']) 
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('The password repeat minimum has not been set');
        }
        $this->_udfPasswordPolicy['password_repeat_minimum'] = $entropyObj['password_repeat_minimum'];

        //validate that password repeat minimum has correct indices, then set it
        if(!isset($entropyObj['illegal_attempts_penalty_seconds'])
            || !is_int($entropyObj['illegal_attempts_penalty_seconds']) 
        ) {
            //TODO: throw exception here
            throw new UserCredentialException('The illegal attempts penalty seconds has not been set');
        }
        $this->_udfPasswordPolicy['illegal_attempts_penalty_seconds'] = $entropyObj['illegal_attempts_penalty_seconds'];
    }    
	
    /**
     * function getUdfEntropy() = Get the udf entropy data structure
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @return array / Object
     * 
     * @access protected
     * @final
     */
    final protected function _getUdfEntropy() {
        if(isset($this->_udfEntropySetting)){
            return $this->_udfEntropySetting;
        }
    }
    
     /**
     * function getUdfPasswordPolicy() = Get the udf password policy
     * Cyril Ogana <cogana@gmail.com>
     * 2014-02-11
     *
     * @return array / Object
     * 
     * @access protected
     * @final
     */
    final protected function _getUdfPasswordPolicy() {
        if(isset($this->_udfPasswordPolicy)){
            return $this->_udfPasswordPolicy;
        }
    }  
	
    /**
     * function setBaseEntropyOverride() = Set the value of base entropy
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @param  bool toggle - True or false to toggle the attribute
     *
     * @return void
     * 
     * @access protected
     * @final
     */
    final protected function _setBaseEntropyOverride($toggle) {
        if(isset($this->_baseEntropyOverride)
           && is_bool($toggle)
        ){
            $this->_baseEntropyOverride = $toggle;   
        }
    }

    /**
     * function getBaseEntropyOverride = Get the current value of base entropy override attrib
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @return bool
     * 
     * @access protected
     * @final
     */
    final protected function _getBaseEntropyOverride() {
	if(isset($this->_baseEntropyOverride)){
            return $this->_baseEntropyOverride;
        }
    }
	
    /**
     * function regexBuildPattern() - build simple regex patterns based on the settings
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @param  int patternCode - integer representing defined constants for variable code
     * @param  int matchCount  - integer representing the count of matched transactions
     * 
     * @return string
     *
     * @access private
     */	
    private function _regexBuildPattern($patternCode, $matchCount){
        $patternRegex = '';

        switch($patternCode) {
            case 1:
                $patternRegex = "(?=(?:.*[A-Z]){{$matchCount}})";
            break;
            case 2:
                $patternRegex = "(?=(?:.*[a-z]){{$matchCount}})";
            break;
            case 3:
                $patternRegex = "(?=(?:.*[0-9]){{$matchCount}})";
            break;
            case 4:
                $patternRegex = '(?=(?:.*([-@%+\/\'!#$^*?:.)(}{\[\]~_])){'.$matchCount.'})';
            break;
            default:
            break;
        }
        if(!(isset($patternRegex))){
            //TODO: Throw exception here
            throw new UserCredentialException('The regex pattern is not set');
        }

        return $patternRegex;
    }
    
    /**
    * function _getPasswordEntropyDescription() - get a description of the required password entropy
    * Cyril Ogana <cogana@gmail.com>
    * 2014-02-11
    *    
    * @return string
    *
    * @access protected
    * @final
    */	
    final protected function  _getPasswordEntropyDescription(){
        $entropyObj = $this->_getUdfEntropy();
        
        $description    = 'The password entropy requires at minimum, the following: ';
        $hasEntropy     = false;
        $isFirstEntropy = false;
        $concatenator   = '';
        
        if($entropyObj['lowercase']['min_len']){
            $lowercaseLen   = $entropyObj['lowercase']['min_len'];
            $description   .= " at least $lowercaseLen lowercase characters";
            $hasEntropy     = true;
            $isFirstEntropy = true;
        }
        
        if($entropyObj['uppercase']['min_len']){
            $isFirstEntropy = $isFirstEntropy == true ? false : true;
            $concatenator   = $isFirstEntropy == true ? ''    : ',';
            $uppercaseLen   = $entropyObj['uppercase']['min_len'];
            $description   .= "$concatenator at least $uppercaseLen uppercase characters";
            $hasEntropy     = true;     
        }
        
        if($entropyObj['numeric']['min_len']){
            $isFirstEntropy = $isFirstEntropy == true ? false : true;
            $concatenator   = $isFirstEntropy == true ? ''    : ',';
            $numericLen     = $entropyObj['numeric']['min_len'];
            $description   .= "$concatenator at least $numericLen numeric characters";
            $hasEntropy     = true;     
        }

        if($entropyObj['special']['min_len']){
            $isFirstEntropy = $isFirstEntropy == true ? false : true;
            $concatenator   = $isFirstEntropy == true ? ''    : ',';
            $specialLen     = $entropyObj['special']['min_len'];
            $description   .= "$concatenator at least $specialLen special characters";
            $hasEntropy     = true;     
        }
        
        if(!$hasEntropy){
            $description = 'There is no minimum password entropy policy in place';
        }
        
        return $description;
    }

    /**
    * function _getPasswordLengthDescription() - get a description of the required password entropy
    * Cyril Ogana <cogana@gmail.com>
    * 2014-02-11
    *    
    * @return string
    *
    * @access protected
    * @final
    */    
    final protected function _getPasswordLengthDescription(){
        $entropyObj = $this->_getUdfEntropy();
        
        if($entropyObj['min_pass_len']){
            return "The minimum password length is {$entropyObj['min_pass_len']} characters";
        }else{
            return 'There is no minimum password length policy in place';
        }
    }

    final protected function _getPasswordPolicyDescription($policyType){
        $policyObj = $this->_getUdfPasswordPolicy();

        switch($policyType) {
            case 'illegal_attempts_limit':
                if($policyObj['illegal_attempts_limit']){
                    return 'The illegal login attempts limit is '.$policyObj['illegal_attempts_limit'];
                }
            break;
            case 'password_reset_frequency':
                if($policyObj['password_reset_frequency']){
                    return 'The password reset frequency is '.$policyObj['password_reset_frequency'].' days';
                }
            break;
            case 'password_repeat_minimum':
                if($policyObj['password_repeat_minimum']){
                    return 'A user is not allowed to repeat any of their last '.$policyObj['password_repeat_minimum'].' passwords';
                }
            break;
            case 'illegal_attempts_penalty_seconds':
                if($policyObj['illegal_attempts_penalty_seconds']){
                    return 'A user account will be temporarily locked out after the illegal login attempts limit for '.$policyObj['illegal_attempts_penalty_seconds'].' seconds; and will require admin intervention if the offense is repeated';
                }
            break;
            default:
            
            break;
        }
    }
 
    /**
     * function validateEntropy() - validate the entropy of the password in the userprofile
     * Cyril Ogana <cogana@gmail.com>
     * 2013-05-13
     *
     * @return bool
     *
     * @access protected
     * @final
     */
     final protected function _validateEntropy(){
        //validate that required indices exist
        if(!isset($this->_userProfile['username'])
               || !isset($this->_userProfile['password'])
               || !isset($this->_userProfile['fullname'])
               || !isset($this->_userProfile['passhist'])
            ) {
                //TODO: Throw exception here
            throw new Exception('The username and password are not set');
        }

        //validate that user is not using part of username as password
        $namePartsArr = array();
        $namePartsArr[] = strtolower($this->_userProfile['username']);
        $namePartsArr[] = strtolower($this->_userProfile['fullname']);
        $namePartsArr[] = strtolower(str_replace(' ', '', $this->_userProfile['fullname']));
        
        $fullNameExploded = explode(' ', $this->_userProfile['fullname']);
        
        foreach ($fullNameExploded as $nameItem) {
            $namePartsArr[] = strtolower($nameItem);
        }
        
        foreach ($namePartsArr as $namePart) {
            $namePartCast = (string) $namePart;
            
            if ((strpos(strtolower($this->_userProfile['password']), $namePartCast)) !== false) {
                throw new UserCredentialException('Password cannot contain username or any of your names', \USERCREDENTIAL_ACCOUNTPOLICY_NAMEINPASSWD);
            }
        }
        //determine which entropy to use (base or udf)
        $entropyObj = $this->_udfEntropySetting;

        $validateCaseRegex = '';
        $upperCaseRegex    = '';

        //build the password entropy regex uppercase
        if($entropyObj['uppercase']['toggle'] == true){
            //@TODO: Implement as constants the patterns
            $pattern    = 1;
            $matchCount = ($entropyObj['uppercase']['min_len'] ? $entropyObj['uppercase']['min_len'] : 1);
            $upperCaseRegex = $this->_regexBuildPattern($pattern, $matchCount);
        }

        $lowerCaseRegex = '';

        //build the password entropy regex lowercase
        if($entropyObj['lowercase']['toggle'] == true){
            $pattern    = 2;
            $matchCount = ($entropyObj['lowercase']['min_len'] ? $entropyObj['lowercase']['min_len'] : 1);
            $lowerCaseRegex = $this->_regexBuildPattern($pattern,$matchCount);
        }

        $numericRegex = '';

        //build the password entropy regex numbers
        if($entropyObj['numeric']['toggle'] == true){
            $pattern    = 3;
            $matchCount = ($entropyObj['numeric']['min_len'] ? $entropyObj['numeric']['min_len'] : 1);
            $numericRegex = $this->_regexBuildPattern($pattern, $matchCount);
        }

        $specialRegex = '';

        //build the password entropy regex special
        if($entropyObj['special']['toggle'] == true){
            $pattern    = 4;
            $matchCount = ($entropyObj['special']['min_len'] ? $entropyObj['special']['min_len'] : 1);
            $specialRegex = $this->_regexBuildPattern($pattern, $matchCount);
        }

        //regex entropy string

        $validateCaseRegex = '/^'.$upperCaseRegex.$lowerCaseRegex.$numericRegex.$specialRegex.'/';
        $testVal = preg_match($validateCaseRegex,$this->_userProfile['password']);

        if ($testVal === false) {
            throw new UserCredentialException('A fatal error occured in the password validation', 0);
        } elseif($testVal == false) {
            throw new UserCredentialException('The password does not meet the minimum entropy. '. $this->_getPasswordEntropyDescription(), \USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD);
        } else {
            return true;
        }
    }
    
    final protected function _validateLength() {
        //validate that required indices exist
        if(!isset($this->_userProfile['username'])
               || !isset($this->_userProfile['password'])
               || !isset($this->_userProfile['fullname'])
               || !isset($this->_userProfile['passhist'])
            ) {
                //TODO: Throw exception here
            throw new Exception('The username and password are not set');
        }

        //determine which entropy to use (base or udf)
        $entropyObj = $this->_udfEntropySetting;
        
        if (strlen($this->_userProfile['password']) < $entropyObj['min_pass_len']) {
            throw new UserCredentialException('The password does not meet required length. '.$this->_getPasswordLengthDescription());
        }
        
        return true;
    }
    
    final protected function _validatePolicy() {
        //validate that required indices exist
        if(!isset($this->_userProfile['username'])
               || !isset($this->_userProfile['password'])
               || !isset($this->_userProfile['fullname'])
               || !isset($this->_userProfile['passhist'])
            ) {
                //TODO: Throw exception here
            throw new Exception('The username and password are not set');
        }

        //determine which entropy to use (base or udf)
        $policyObj = $this->_udfPasswordPolicy;
        
        //check attempt limits
        if ($this->_userProfile['account_state'] == \USERCREDENTIAL_ACCOUNTSTATE_AUTHFAILED) {
            if ($this->_userProfile['policyinfo']['failed_attempt_count'] > $policyObj['illegal_attempts_limit']) {
                throw new UserCredentialException('The account has exceeded login attempts and is locked. Contact admin', \USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT2);
            } elseif ($this->_userProfile['policyinfo']['failed_attempt_count'] == $policyObj['illegal_attempts_limit'])  {
                throw new UserCredentialException('The account has failed login '.(++$policyObj['illegal_attempts_limit']).' times in a row and is temporarily locked. Any further wrong passwords will lead to your account being locked fully. You will be automatically unlocked in '.(($policyObj['illegal_attempts_penalty_seconds']) / 60).' minutes or contact admin to unlock immediately', \USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT1);
            } else {
                throw new UserCredentialException('Login failed. Wrong username or password', \USERCREDENTIAL_ACCOUNTPOLICY_VALID);
            }
        }
        
        //check needs reset
        $currDateTimeObj = new \DateTime();
        $passChangeDaysElapsedObj = $currDateTimeObj->diff($this->_userProfile['policyinfo']['password_last_changed_datetime']);
        $passChangeDaysElapsed = $passChangeDaysElapsedObj->format('%a');
        
        if ($passChangeDaysElapsed > $policyObj['password_reset_frequency']) {
            throw new UserCredentialException('The password has expired and must be changed', \USERCREDENTIAL_ACCOUNTPOLICY_EXPIRED);
        }
        
        return true;        
    }
    
    final protected function _validatePolicyAtChange() {
        //validate that required indices exist
        if(!isset($this->_userProfile['username'])
               || !isset($this->_userProfile['password'])
               || !isset($this->_userProfile['fullname'])
               || !isset($this->_userProfile['passhist'])
            ) {
                //TODO: Throw exception here
            throw new Exception('The username and password are not set');
        }

        //determine which entropy to use (base or udf)
        $policyObj = $this->_udfPasswordPolicy;
        
        //check password repeat
        $passHistory = $this->_userProfile['passhist'];
        $passHistoryRequired = array_slice($passHistory, 0, ((int) $policyObj['password_repeat_minimum']));
        
        foreach ($passHistoryRequired as $passHistoryItem) {
            if (password_verify($this->_userProfile['password'], $passHistoryItem)) {
                throw new UserCredentialException('User cannot repeat any of their ' . $policyObj['password_repeat_minimum'] . ' last passwords', \USERCREDENTIAL_ACCOUNTPOLICY_REPEATERROR);
            }
        }
        
        return true;        
    }
    
    final protected function _canChangePassword() {
         //validate that required indices exist
        if(!isset($this->_userProfile['username'])
               || !isset($this->_userProfile['password'])
               || !isset($this->_userProfile['fullname'])
               || !isset($this->_userProfile['passhist'])
            ) {
            //TODO: Throw exception here
            throw new Exception('The username and password are not set');
        }
  
        //Verify if the password was changed today or server has been futuredated
        $currDateTimeObj = new \DateTime();
        
        //Password was changed today or in the future
        if ($currDateTimeObj <= $this->_userProfile['policyinfo']['password_last_changed_datetime']) {
            return false;
        } else {
            return true;
        }
    }
    
    /**
        * Abstract functions
        */
    abstract public function getBaseEntropy();
    abstract public function getBaseEntropyOverride();
    abstract public function getBasePasswordPolicy();
    abstract public function getPasswordEntropyDescription();
    abstract public function getPasswordLengthDescription();
    abstract public function getPasswordPolicyDescription();
    abstract public function getUdfEntropy();
    abstract public function getUdfPasswordPolicy();
    abstract public function setBaseEntropyOverride($toggle);
    abstract public function setUdfEntropy($entropyObj);
    abstract public function setUdfPasswordPolicy($entropyObj);
    abstract public function validateEntropy();
    abstract public function validateLength();
    abstract public function validatePolicy();
    abstract public function validatePolicyAtChange();
    abstract public function canChangePassword();
}

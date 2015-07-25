<?php
namespace cymapgt\core\application\authentication\UserCredential\abstractclass;

use cymapgt\Exception\UserCredentialException;
use Phpass\Strength;

/**
 * This package implements user password policy and credential management as well as
 * 2 factor authentication using TOTP
 *
 * @category    security
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2015 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
 * Exception@1025
 * 
 *      - See http://www.owasp.org/images/0/08/OWASP_SCP_Quick_Reference_Guide_v2.pdf 
 *           (authentication section)
 */

abstract class UserCredentialAbstract
{
    private $_userProfile         = array();      //Array containing user information to use in the class
    
    private $_baseEntropySetting  = array();      //This is the default entropy setting
    private $_baseEntropyOverride = false;        //A flag to turn off base entropy enforcement 
    private $_udfEntropySetting   = array();      //A variable to store the user defined entropy

    private $_basePasswordPolicy  = array();      //Base password policy maintained by UserCredential class
    private $_udfPasswordPolicy   = array();      //Udf password policy input by the user
	
        
    /*
     * Constructor method
     * Cyril Ogana <cogana@gmail.com> - 2015-07-18
     * 
     * @param array userProfile - array of user credential information
     */
    public function __construct($userProfile) {
        $this->_initialize($userProfile);
    }
	
    /**
     * Initialize the classes default settings (base entropy)
     * Cyril Ogana <cogana@gmail.com> - 2015-07-18
     *
     * @param array /ArrayAccess  userProfile
     *
     * @access private
     */             
    private function _initialize($userProfile) {
        $this->_initializeProfile($userProfile);
        $this->_initializeBaseEntropy();
        $this->_initializeBasePasswordPolicy();
    }
	
   /** 
    * initializes the user profiles data as per the user credentials provided to the constructor method
    * 
    * Cyril Ogana <cogana@gmail.com> - 2015-07-18
    *
    * @param  array / ArrayAccess  $userProfile
    *
    * @access private
    */
    private function _initializeProfile($userProfile) {
        //validate that user profile has the correct information for password validation
        if (!is_array($userProfile)
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
            throw new UserCredentialException('The user profile is not properly initialized', 1000);
        }
        
        //set a blank TOTP profile if not set
        if (!isset($userProfile['totpinfo'])) {
            $userProfile['totpinfo'] = array();
        }
        
        $this->_userProfile = $userProfile;
    }

    /**
     * Initialize entopy requirements to recommended default base entropy  as per OWASP
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @access private
     */ 	
    private function _initializeBaseEntropy() {
        //initialize if not already initialized as array
        if (!is_array($this->_baseEntropySetting)) {
            $this->_baseEntropySetting = array();
        }

        $this->_baseEntropySetting['min_pass_len'] = 8;    //minimum password length
        $this->_baseEntropySetting['max_consecutive_chars'] = 2;    //minimum characters to repeat consecutively
        $this->_baseEntropySetting['uppercase'] = array (     //requirement and length for various character types
            'toggle'  => true,
            'min_len' => 2
        );
        $this->_baseEntropySetting['numeric'] = array(
            'toggle'  => true,
            'min_len' => 1														
        );
        $this->_baseEntropySetting['lowercase'] = array(
            'toggle'  => true,
            'min_len' => 2
        );
        $this->_baseEntropySetting['special'] = array(
            'toggle'  => true,
            'min_len' => 1
        );
        
        $this->_baseEntropySetting['multi_factor_on'] = false; //whether multi-factor auth is on or off
        $this->_baseEntropySetting['multi_factor_enc_key_length'] = 20; //length of encryption key generated when verifying token
                
        $this->_baseEntropyOverride = false;    //override the reommended settings?
        $this->_setUdfEntropy($this->_baseEntropySetting);
    }
    
    /**
     * Initialize policy requirements to recommended default base entropy  as per OWASP
     * Cyril Ogana <cogana@gmail.com>
     * 2014-02-11
     *
     * @access private
     */ 	
    private function _initializeBasePasswordPolicy() {
        $this->_basePasswordPolicy['illegal_attempts_limit'] = 3; //count
        $this->_basePasswordPolicy['password_reset_frequency'] = 45; //days
        $this->_basePasswordPolicy['password_repeat_minimum'] = 5; //count
        $this->_basePasswordPolicy['illegal_attempts_penalty_seconds'] = 600; //seconds
        $this->_setUdfPasswordPolicy($this->_basePasswordPolicy);
    }
    
    /**
     * Get the base entropy data structure
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return array / Object
     * 
     * @access protected
     * @final
     */
    final protected function _getBaseEntropy() {
	if (isset($this->_baseEntropySetting)) {
            return $this->_baseEntropySetting;
        }
    }
    
    /**
     *  Get the base password policy
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return array / Object
     * 
     * @access protected
     * @final
     */
    final protected function _getBasePasswordPolicy() {
	if (isset($this->_basePasswordPolicy)) {
            return $this->_basePasswordPolicy;
        }
    }  

    /**
     * Set the user defined entropy setting
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @param  array / object entropyObj - array or object implementing ArrayAccess
     *
     * @access protected
     * @final
     */ 
     final protected function _setUdfEntropy($entropyObj) {
        //initialize if not already initialized as array
        if (!is_array($this->_udfEntropySetting)
           ||
           (!is_object($this->_udfEntropySetting)
            &&
            $this->_udfEntropySetting instanceof \ArrayAccess)
        ) {
            $this->_udfEntropySetting = array();
        }

        //validate the array / object
        if (!is_array($entropyObj)) {
            if (!is_object($entropyObj)
                || !($entropyObj instanceof \ArrayAccess)
            ) {
                throw new UserCredentialException('The entropy object should be an array or implement ArrayAccess interface', 1001);
            }
        }

        //validate that minimum password len has the correct indices, then set it
        if (!isset($entropyObj['min_pass_len'])
            || !is_int($entropyObj['min_pass_len']) 
        ) {
            throw new UserCredentialException('The minimum password length hasn\'t been set', 1002);
        }
        $this->_udfEntropySetting['min_pass_len'] = $entropyObj['min_pass_len'];

        //validate that minimum allowed password characters to repeat has been set
        if (!isset($entropyObj['max_consecutive_chars'])
            || !is_int($entropyObj['max_consecutive_chars'])
        ) {
            throw new UserCredentialException('The minimum allowed consecutive character repetition hasn\'t been set', 1003);
        }
        
        $this->_udfEntropySetting['max_consecutive_chars'] =  $entropyObj['max_consecutive_chars'];
        
        //validate that uppercase snippet has correct indices, then set it
        if (!isset($entropyObj['uppercase'])
            || !is_array($entropyObj['uppercase'])
            || !isset($entropyObj['uppercase']['toggle'])
            || !is_bool($entropyObj['uppercase']['toggle'])
            || !isset($entropyObj['uppercase']['min_len'])
            || !is_int($entropyObj['uppercase']['min_len'])
        ) {
            throw new UserCredentialException('The uppercase settings must be an array containing toggle and min upper length', 1004);
        }
        $this->_udfEntropySetting['uppercase'] = $entropyObj['uppercase'];

        //validate that lowercase snippet has correct indices, then set it
        if (!isset($entropyObj['lowercase'])
           || !is_array($entropyObj['lowercase'])
           || !isset($entropyObj['lowercase']['toggle'])
           || !is_bool($entropyObj['lowercase']['toggle'])
           || !isset($entropyObj['lowercase']['min_len'])
           || !is_int($entropyObj['lowercase']['min_len'])
        ) {
            throw new UserCredentialException('The lowercase settings must be an array containing toggle and min lower length', 1005);
        }
        $this->_udfEntropySetting['lowercase'] = $entropyObj['lowercase'];

        //validate that numeric chars snippet has correct indices, then set it
        if (!isset($entropyObj['numeric'])
            || !is_array($entropyObj['numeric'])
            || !isset($entropyObj['numeric']['toggle'])
            || !is_bool($entropyObj['numeric']['toggle'])
            || !isset($entropyObj['numeric']['min_len'])
            || !is_int($entropyObj['numeric']['min_len'])
        ) {
            throw new UserCredentialException('The numeric settings must be an array containing toggle and min lower length', 1006);
        }
        $this->_udfEntropySetting['numeric'] = $entropyObj['numeric'];

        //validate that special chars snippet has correct indices, then set it
        if (!isset($entropyObj['special'])
            || !is_array($entropyObj['special'])
            || !isset($entropyObj['special']['toggle'])
            || !is_bool($entropyObj['special']['toggle'])
            || !isset($entropyObj['special']['min_len'])
            || !is_int($entropyObj['special']['min_len'])
        ) {
            throw new UserCredentialException('the special character settings must be an array containing toggle and min length', 1007);
        }
        $this->_udfEntropySetting['special'] = $entropyObj['special'];
        
        //in case we are using multi-factor, validate that all options are set
        if (
            isset($entropyObj['multi_factor_on'])
            && $entropyObj['multi_factor_on'] === true
        ) {
            //encryption key length
            if (
                !isset($entropyObj['multi_factor_enc_key_length'])
                || !(is_int($entropyObj['multi_factor_enc_key_length']))
                || !($entropyObj['multi_factor_enc_key_length'] >= 16)
            ) {
                throw new UserCredentialException('Multi factor auth is flagged on, but the encryption key length is not properly initialized!', 1023);
            }

            $this->_udfEntropySetting['multi_factor_on'] = $entropyObj['multi_factor_on'];
            $this->_udfEntropySetting['multi_factor_enc_key_length'] = $entropyObj['multi_factor_enc_key_length'];
        }
    }
    
    /**
     * Set the user defined password policy
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @param  array / object entropyObj - array or object implementing ArrayAccess
     *
     * @access protected
     * @final
     */ 
     final protected function _setUdfPasswordPolicy($entropyObj) {
        //initialize if not already initialized as array
        if (!is_array($this->_udfPasswordPolicy)
           || 
           (!is_object($this->_udfPasswordPolicy)
            &&
            $this->_udfPasswordPolicy instanceof \ArrayAccess)
        ) {
            $this->_udfPasswordPolicy = array();
        }

        //validate the array / object
        if (!is_array($entropyObj)) {
            if(!is_object($entropyObj)
                || !($entropyObj instanceof \ArrayAccess)
            ) {
                throw new UserCredentialException('The entropy object should be an array or implement ArrayAccess interface', 1008);
            }
        }

        //validate that illegal attempts limit has correct indices, then set it
        if (!isset($entropyObj['illegal_attempts_limit'])
            || !is_int($entropyObj['illegal_attempts_limit'])
        ) {
            throw new UserCredentialException('The illegal attempts limit hasn\'t been set', 1009);
        }
        $this->_udfPasswordPolicy['illegal_attempts_limit'] = $entropyObj['illegal_attempts_limit'];

        //validate that password reset frequency has correct indices, then set it
        if (!isset($entropyObj['password_reset_frequency'])
            || !is_int($entropyObj['password_reset_frequency']) 
        ) {
            throw new UserCredentialException('The password reset frequency hasn\'t been set', 1010);
        }
        $this->_udfPasswordPolicy['password_reset_frequency'] = $entropyObj['password_reset_frequency'];

        //validate that passwordd repeat minimum has correct indices, then set it
        if (!isset($entropyObj['password_repeat_minimum'])
            || !is_int($entropyObj['password_repeat_minimum']) 
        ) {
            throw new UserCredentialException('The password repeat minimum has not been set', 1011);
        }
        $this->_udfPasswordPolicy['password_repeat_minimum'] = $entropyObj['password_repeat_minimum'];

        //validate that password repeat minimum has correct indices, then set it
        if(!isset($entropyObj['illegal_attempts_penalty_seconds'])
            || !is_int($entropyObj['illegal_attempts_penalty_seconds']) 
        ) {
            throw new UserCredentialException('The illegal attempts penalty seconds has not been set', 1012);
        }
        $this->_udfPasswordPolicy['illegal_attempts_penalty_seconds'] = $entropyObj['illegal_attempts_penalty_seconds'];
    }
	
    /**
     * Get the udf entropy data structure
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return array / Object
     * 
     * @access protected
     * @final
     */
    final protected function _getUdfEntropy() {
        if (isset($this->_udfEntropySetting)) {
            return $this->_udfEntropySetting;
        }
    }
    
     /**
     * Get the udf password policy
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return array / Object
     * 
     * @access protected
     * @final
     */
    final protected function _getUdfPasswordPolicy() {
        if (isset($this->_udfPasswordPolicy)) {
            return $this->_udfPasswordPolicy;
        }
    }  
	
    /**
     * Set the value of base entropy toggle flag
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @param True or false to toggle the attribute
     *
     * @return void
     * 
     * @access protected
     * @final
     */
    final protected function _setBaseEntropyOverride($toggle) {
        if (isset($this->_baseEntropyOverride)
           && is_bool($toggle)
        ) {
            $this->_baseEntropyOverride = $toggle;   
        }
    }

    /**
     * Get the current value of base entropy override attrib
     * Cyril Ogana <cogana@gmail.com>
     * 2013-07-18
     *
     * @return bool
     * 
     * @access protected
     * @final
     */
    final protected function _getBaseEntropyOverride() {
	if (isset($this->_baseEntropyOverride)) {
            return $this->_baseEntropyOverride;
        }
    }
	
    /**
     * build simple regex patterns based on particular entropy settings
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @param  int patternCode - integer representing defined constants for variable code
     * @param  int matchCount  - integer representing the count of matched transactions
     * 
     * @return string
     *
     * @access private
     */	
    private function _regexBuildPattern($patternCode, $matchCount) {
        $patternRegex = '';

        switch ($patternCode) {
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
            case 5:
                $patternRegex = '((.)\2}?(\2{'.$matchCount.'}))';
            default:
            break;
        }
        if (!(isset($patternRegex))) {
            throw new UserCredentialException('The regex pattern is not set', 1013);
        }

        return $patternRegex;
    }
    
    /**
    * Get a description of the required password entropy
    * Cyril Ogana <cogana@gmail.com>
    * 2015-07-18
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
        
        if ($entropyObj['lowercase']['min_len']) {
            $lowercaseLen   = $entropyObj['lowercase']['min_len'];
            $description   .= " at least $lowercaseLen lowercase characters";
            $hasEntropy     = true;
            $isFirstEntropy = true;
        }
        
        if ($entropyObj['uppercase']['min_len']) {
            $isFirstEntropy = $isFirstEntropy == true ? false : true;
            $concatenator   = $isFirstEntropy == true ? ''    : ',';
            $uppercaseLen   = $entropyObj['uppercase']['min_len'];
            $description   .= "$concatenator at least $uppercaseLen uppercase characters";
            $hasEntropy     = true;     
        }
        
        if ($entropyObj['numeric']['min_len']) {
            $isFirstEntropy = $isFirstEntropy == true ? false : true;
            $concatenator   = $isFirstEntropy == true ? ''    : ',';
            $numericLen     = $entropyObj['numeric']['min_len'];
            $description   .= "$concatenator at least $numericLen numeric characters";
            $hasEntropy     = true;     
        }

        if ($entropyObj['special']['min_len']) {
            $isFirstEntropy = $isFirstEntropy == true ? false : true;
            $concatenator   = $isFirstEntropy == true ? ''    : ',';
            $specialLen     = $entropyObj['special']['min_len'];
            $description   .= "$concatenator at least $specialLen special characters";
            $hasEntropy     = true;     
        }
        
        if (!$hasEntropy) {
            $description = 'There is no minimum password entropy policy in place';
        }
        
        return $description;
    }

    /**
    * Get a description of the required password entropy
    * Cyril Ogana <cogana@gmail.com>
    * 2015-07-18
    *    
    * @return string
    *
    * @access protected
    * @final
    */    
    final protected function _getPasswordLengthDescription(){
        $entropyObj = $this->_getUdfEntropy();
        
        if ($entropyObj['min_pass_len']) {
            return "The minimum password length is {$entropyObj['min_pass_len']} characters";
        } else {
            return 'There is no minimum password length policy in place';
        }
    }
    
    /**
     * Get a description for the entropy policy regarding repeating a character consecutively
     * Cyril Ogana<cogana@gmail.com>
     * 2015-07-18
     * 
     * @return string
     * 
     * @access protected
     * @final
     */
    final protected function _getPasswordCharacterRepeatDescription() {
        $entropyObj = $this->_getUdfEntropy();
        
        if ($entropyObj['max_consecutive_chars']) {
            return "The maximum allowed number of repeated characters in password of same type (e.g. aaa) is {$entropyObj['max_consecutive_chars']}";
        } else {
            return "There is no maximum allowed number of repeated characters in password of the same type (e.g. aaa)";
        }
    }

    /**
    * Get a description of the required password policy
    * Cyril Ogana <cogana@gmail.com>
    * 2015-07-18
    *    
    * @return string
    *
    * @access protected
    * @final
    */        
    final protected function _getPasswordPolicyDescription($policyType){
        $policyObj = $this->_getUdfPasswordPolicy();

        switch ($policyType) {
            case 'illegal_attempts_limit':
                if ($policyObj['illegal_attempts_limit']) {
                    return 'The illegal login attempts limit is '.$policyObj['illegal_attempts_limit'];
                }
            break;
            case 'password_reset_frequency':
                if ($policyObj['password_reset_frequency']) {
                    return 'The password reset frequency is '.$policyObj['password_reset_frequency'].' days';
                }
            break;
            case 'password_repeat_minimum':
                if ($policyObj['password_repeat_minimum']) {
                    return 'A user is not allowed to repeat any of their last '.$policyObj['password_repeat_minimum'].' passwords';
                }
            break;
            case 'illegal_attempts_penalty_seconds':
                if ($policyObj['illegal_attempts_penalty_seconds']) {
                    return 'A user account will be temporarily locked out after the illegal login attempts limit for '.$policyObj['illegal_attempts_penalty_seconds'].' seconds; and will require admin intervention if the offense is repeated';
                }
            break;
            default:
            
            break;
        }
    }
 
    /**
     * validate the entropy of the password in the userprofile
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return bool
     *
     * @access protected
     * @final
     */
     final protected function _validateEntropy(){
        //validate that required indices exist
        if (!isset($this->_userProfile['username'])
            || !isset($this->_userProfile['password'])
            || !isset($this->_userProfile['fullname'])
            || !isset($this->_userProfile['passhist'])
        ) {
            throw new Exception('The username and password are not set', 1014);
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
        
        //iterate and search for occurrences of name parts
        foreach ($namePartsArr as $namePart) {
            $namePartCast = (string) $namePart;
            
            if ((strpos(strtolower($this->_userProfile['password']), $namePartCast)) !== false) {
                throw new UserCredentialException('Password cannot contain username or any of your names', \USERCREDENTIAL_ACCOUNTPOLICY_NAMEINPASSWD);
            }
        }
        //set which entropy to use (base or udf)
        $entropyObj = $this->_udfEntropySetting;

        $validateCaseRegex = '';
        $upperCaseRegex    = '';

        //build the password entropy regex uppercase
        if ($entropyObj['uppercase']['toggle'] == true) {
            //@TODO: Implement as constants the patterns
            $pattern    = 1;
            $matchCount = ($entropyObj['uppercase']['min_len'] ? $entropyObj['uppercase']['min_len'] : 1);
            $upperCaseRegex = $this->_regexBuildPattern($pattern, $matchCount);
        }

        $lowerCaseRegex = '';

        //build the password entropy regex lowercase
        if ($entropyObj['lowercase']['toggle'] == true) {
            $pattern    = 2;
            $matchCount = ($entropyObj['lowercase']['min_len'] ? $entropyObj['lowercase']['min_len'] : 1);
            $lowerCaseRegex = $this->_regexBuildPattern($pattern,$matchCount);
        }

        $numericRegex = '';

        //build the password entropy regex numbers
        if ($entropyObj['numeric']['toggle'] == true) {
            $pattern    = 3;
            $matchCount = ($entropyObj['numeric']['min_len'] ? $entropyObj['numeric']['min_len'] : 1);
            $numericRegex = $this->_regexBuildPattern($pattern, $matchCount);
        }

        $specialRegex = '';

        //build the password entropy regex special
        if ($entropyObj['special']['toggle'] == true) {
            $pattern    = 4;
            $matchCount = ($entropyObj['special']['min_len'] ? $entropyObj['special']['min_len'] : 1);
            $specialRegex = $this->_regexBuildPattern($pattern, $matchCount);
        }

        //regex entropy string

        $validateCaseRegex = '/^'.$upperCaseRegex.$lowerCaseRegex.$numericRegex.$specialRegex.'/';
        $testVal = preg_match($validateCaseRegex,$this->_userProfile['password']);

        if ($testVal === false) {
            throw new UserCredentialException('A fatal error occured in the password validation', 1015);
        } elseif ($testVal == false) {
            throw new UserCredentialException('The password does not meet the minimum entropy. '. $this->_getPasswordEntropyDescription(), \USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD);
        } else {
            return true;
        }
    }
    
    /**
     * Validate entropy of TOTP parameters in the profile
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-24
     * 
     * @return bool
     * 
     * @access protected
     * @final
     */
    final protected function _validateEntropyTotp() {
        //in case we are using multi-factor, validate that all options are set
        if (
            isset($this->_udfEntropySetting['multi_factor_on'])
            && $this->_udfEntropySetting['multi_factor_on'] === true
        ) {
            //encryption key length
            if (
                !(count($this->_userProfile['totpinfo']))
                || !(isset($this->_userProfile['totpinfo']['enc_key']))
            ) {
                throw new UserCredentialException('TOTP info is not set in the users profile', 1024);
            }
            
            //validate length of encryption key
            $encKeyLength = $this->_udfEntropySetting['multi_factor_enc_key_length'];
            
            if (!strlen($this->_userProfile['totpinfo']['enc_key']) >= $encKeyLength) {
                throw new UserCredentialException('The encryption key string length for TOTP hashing is too short', 1025);
            }
        }
        
        return true;
    }
    
    /**
     * validate the password length of the users credentials
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return bool
     *
     * @access protected
     * @final
     */    
    final protected function _validateLength() {
        //validate that required indices exist
        if (!isset($this->_userProfile['username'])
            || !isset($this->_userProfile['password'])
            || !isset($this->_userProfile['fullname'])
            || !isset($this->_userProfile['passhist'])
        ) {
            throw new Exception('The username and password are not set', 1016);
        }

        //determine which entropy to use (base or udf)
        $entropyObj = $this->_udfEntropySetting;
        
        //perform length check
        if (strlen($this->_userProfile['password']) < $entropyObj['min_pass_len']) {
            throw new UserCredentialException('The password does not meet required length. '.$this->_getPasswordLengthDescription(), \USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD);
        }
        
        return true;
    }
    
    /**
     * validate that there are no instances of consecutive character repetitions beyond allowed number
     * in the users password string
     * 
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return bool
     *
     * @access protected
     * @final
     */      
    final protected function _validateConsecutiveCharacterRepeat() {
        //validate that required indices exist
        if (!isset($this->_userProfile['username'])
            || !isset($this->_userProfile['password'])
            || !isset($this->_userProfile['fullname'])
            || !isset($this->_userProfile['passhist'])
        ) {
            throw new Exception('The username and password are not set', 1017);
        }

        //determine which entropy to use (base or udf)
        $entropyObj = $this->_udfEntropySetting;
        $maxConsecutiveChars = (int) ($entropyObj['max_consecutive_chars']);
        
        //because we offset by -2 when doing regex, if the limit is not greater or equal to 2, default to 2
        if (!($maxConsecutiveChars >= 2)) {
            $maxConsecutiveChars = 2;
        }
        
        //offset for purposes of matching (TODO: fix?)
        $maxConsecutiveCharsRegexOffset = ++$maxConsecutiveChars - 2;
        
        //build regex
        $maxConsecutiveCharsRegex = '/' . $this->_regexBuildPattern(5, $maxConsecutiveCharsRegexOffset) . '/';
        //die(print_r($maxConsecutiveCharsRegex));
        $testVal = preg_match($maxConsecutiveCharsRegex,$this->_userProfile['password']);

        if ($testVal === false) {
            throw new UserCredentialException('A fatal error occured in the password validation', 1018);
        } elseif ($testVal == true) {
            throw new UserCredentialException('The password violates policy about consecutive character repetitions. '. $this->_getPasswordCharacterRepeatDescription(), \USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD);
        } else {
            return true;
        }        
        
        return true;
    }
    
    /**
     * validate the password policy during authentication
     * 
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return bool
     *
     * @access protected
     * @final
     */    
    final protected function _validatePolicy() {
        //validate that required indices exist
        if (!isset($this->_userProfile['username'])
            || !isset($this->_userProfile['password'])
            || !isset($this->_userProfile['fullname'])
            || !isset($this->_userProfile['passhist'])
         ) {
            throw new Exception('The username and password are not set', 1019);
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
    
    /**
     * validate the password policy during process of making a password change
     * 
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return bool
     *
     * @access protected
     * @final
     */      
    final protected function _validatePolicyAtChange() {
        //validate that required indices exist
        if (!isset($this->_userProfile['username'])
            || !isset($this->_userProfile['password'])
            || !isset($this->_userProfile['fullname'])
            || !isset($this->_userProfile['passhist'])
         ) {
            throw new Exception('The username and password are not set', 1020);
        }

        //determine which entropy to use (base or udf)
        $policyObj = $this->_udfPasswordPolicy;
        
        //check password repeat
        $passHistory = $this->_userProfile['passhist'];
        $passHistoryRequired = array_slice($passHistory, 0, ((int) $policyObj['password_repeat_minimum']));
        
        //iterate and verify
        foreach ($passHistoryRequired as $passHistoryItem) {
            if (password_verify($this->_userProfile['password'], $passHistoryItem)) {
                throw new UserCredentialException('User cannot repeat any of their ' . $policyObj['password_repeat_minimum'] . ' last passwords', \USERCREDENTIAL_ACCOUNTPOLICY_REPEATERROR);
            }
        }
        
        return true;        
    }
    
    /**
     * Check that a user can change password in case you want to implement limits on changing passwords
     * only once in 24 hours
     * 
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     *
     * @return bool
     *
     * @access protected
     * @final
     */       
    final protected function _canChangePassword() {
         //validate that required indices exist
        if (!isset($this->_userProfile['username'])
            || !isset($this->_userProfile['password'])
            || !isset($this->_userProfile['fullname'])
            || !isset($this->_userProfile['passhist'])
        ) {
            throw new Exception('The username and password are not set', 1021);
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
     * Check password strength using NIST Or Wolfram adapter (default NIST)
     * See https://github.com/rchouinard/phpass
     * Many thanks to Ryan Chouinard for the phpass package
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-18
     * @param string $passwordString - The password string to evaluate
     * @param int $strengthAdapter - Named constant representing adapter to use (default NIST)
     * 
     * @return int
     * 
     * @access public
     * @static
     */
    public static function passwordStrength($passwordString, $strengthAdapter = \PHPASS_PASSWORDSTRENGTHADAPTER_NIST) {
        if ($strengthAdapter == \PHPASS_PASSWORDSTRENGTHADAPTER_WOLFRAM) {
            $strengthAdapter = new Strength\Adapter\Wolfram;        
        } elseif ($strengthAdapter == \PHPASS_PASSWORDSTRENGTHADAPTER_NIST) {
            $strengthAdapter = new Strength\Adapter\Nist;
        } else {
            throw new Exception('Phpass strength adapter calculator must be NIST or Wolfram. Wrong Flag provivded.', 1022);
        }

        $phpassStrength = new Strength($strengthAdapter);
        return $phpassStrength->calculate($passwordString);
    }
  
    /**
     * Return a cyprographically strong random string of required length
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-24
     * 
     * @return string
     * 
     * @access public
     * @static
     */
    public static function generateRandomKey($keyLength = null) {
        if (
            !(is_int($keyLength))
            && !($keyLength > 0)
        ) {
            throw new UserCredentialException('Key length for random key must be a positive integer');
        }
            
        return openssl_random_pseudo_bytes($keyLength);
    }
    
    /**
     * Generate a 6 digit SMS token
     * Cyril Ogana <cogana@gmail.com>
     * 2015-07-24
     * 
     * @return string
     * 
     * @param string $userName - The username
     * @param string $keyString - String to use as a salt
     * 
     * @access public
     * @static
     */
    public static function generateToken($userName, $keyString) {
        $userNameCast = (string) $userName;
        $keyStringCast = (string) $keyString;
        $multiOtpObj = new MultiotpWrapper($keyStringCast);
        return $multiOtpObj->GenerateSmsToken($userNameCast);
    }
    
    /**
        * Abstract methods for concrete implementation
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
    abstract public function validateEntropyTotp();
    abstract public function validateLength();
    abstract public function validateConsecutiveCharacterRepeat();
    abstract public function validatePolicy();
    abstract public function validatePolicyAtChange();
    abstract public function canChangePassword();
}

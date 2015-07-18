<?php
namespace cymapgt\core\application\authentication\UserCredential\services;

use cymapgt\Exception\UserCredentialException;
use cymapgt\core\application\authentication\UserCredential\abstractclass\UserCredentialAuthenticationInterface;

/**
 * UserCredentialPasswordLoginService
 * This service creates password hashes using the BCRYPT cipher
 *
 * @category    
 * @package     cymapgt.core.application.authentication.UserCredential.services
 * @copyright   Copyright (c) 2014 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
 * 
 * The objectives of the service are
 *  - Create password hash
 *  - Verify password for log in authentication
 *  @TODO provide ability to use AES to encrypt the hash
 */

class UserCredentialPasswordLoginService implements UserCredentialAuthenticationInterface
{
    //flags
    private $_usePasswordFlag = true;  //whether the auth is password based (at some stage or fully)
    private $_multiFactorFlag = false; //whether the auth service is multi factor
    
    //user info
    private $_inputPassword   = ''; //the input password
    private $_currentUsername = ''; //username
    private $_currentPassword = ''; //hashed password
    
    //multi factor auth
    private $_multiFactorHandler = null;    //the handler instance for mutli factor auth
    private $_multiFactorStages  = array(); //the stages of multi factor auth
    
    //Constructor method
    public function __construct() {
        
    }        
  
    /**
     * function setUserPassword() - Specify whether the method uses password
     *                              (set e.g. user log in, lDAP, 2 FACTOR (step 1)
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     *
     * @param bool $flag - if true, is using password
     * 
     * @access public
     */             
    public function setUsePassword($flag) {
        $this->_userPasswordFlag = (bool) $flag;
        $this->_multiFactorFlag  = true;
    }

    /**
     * function getUsePassword() - Return the use password flag
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     *
     * @return bool
     * 
     * @access public
     */             
    public function getUsePassword() {
        return $this->_usePasswordFlag;
    }
    
    /**
     * function setPassword() - Set the user password, and hash it
     *
     * Cyril Ogana <cogana@gmail.com>- 2014-02-13
     *
     * @param bool $password - the user password in raw text
     *
     * @access public
     */             
    public function setPassword($password) {
        $this->_inputPassword = (string) $password;
    }
    
    /**
     * function getPassword()  - Return the hashed user password
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param  $unhashed - flag if true, return unhashed
     * 
     * @return mixed - the hashed password
     * 
     * @access public
     */
    public function getPassword($unhashed = false) {
        if((bool) $unhashed === true){
            return $this->_inputPassword;
        }else{
            return \password_hash($this->_inputPassword, \PASSWORD_DEFAULT);
        }
    }
    
    /**
     * function setMultiFactor($flag) - Set whether this service uses multi factor auth
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param bool $flag - if true, is a multi factor auth service
     * 
     * @access public
     */
    public function setMultiFactor($flag) {
        $this->_multiFactorFlag = (bool) $flag;
    }
    
    /**
     * function setMultiFactorHandler - Provide namespace of the multi factor handler service,
     *                                  which has to implement the interface
     *                                  cymapgt\core\application\authentication\abstractclass\UserCredentialAuthenticationMultiFactorInterface
     *
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param string $handler - The namespace of the multi factor handler service
     * 
     * @access public 
     */
    public function setMultiFactorHandler($handler) {
        $this->_multiFactorHandler = (string) $handler;
    }
    
    /**
     * function getMultiFactorHandler - Return an instance of the multi factor handler service
     *                                  to use ofr this authentication session
     * 
     * Cyril Ogana <cogana@gmail.com > - 2014-02-13
     * 
     * @return object
     * 
     * @access public
     */
    public function getMultiFactorHandler() {
        return $this->_multiFactorHandler;
    }
    
    /**
     * function setMultiFactorStages - in an array, configure the steps of the multifactor login, passing
     *                                 numeric stage names, types and handler calls
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param Array $stages - The stages of the log in session
     * 
     * @access public
     */
    public function setMultiFactorStages(Array $stages) {
        $this->_multiFactorStages = $stages;
    }
    
    /**
     * function getMultiFactorStages - return the multi factor stages array
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @return array
     * 
     * @access public
     */
    public function getMultiFactorStages() {
        return $this->_multiFactorStages;
    }
    
    /**
     * function initialize() - initialize the service, bootstrap before any processing
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @access public
     */
    public function initialize() {
        if(($this->_inputPassword == '')
            && ($this->_currentUsername == '')
            && ($this->_currentPassword == '')
        ){
            throw new UserCredentialException("The usercredential login service is not initialized with all parameters", 2000);
        }
    }
    
    /**
     * function authenticate() - authenticate the user after initialization
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @access public
     */
    public function authenticate() {
        return password_verify($this->_inputPassword, $this->_currentPassword);
    }
    
    /**
     * function setCurrentUsername($username) - set the current username
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param string $username - The current username
     * 
     * @access public
     */
    public function setCurrentUsername($username) {
        $this->_currentUsername = (string) $username;
    }
    
    /**
     * function getCurrentUsername() - get the current username
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-14
     * 
     * @return string - Return the current username
     * 
     * @access public
     */
    public function getCurrentUsername() {
        return $this->_currentUsername;
    }
    
    /**
     * function setCurrentPassword() - set the current password
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-14
     * 
     * @param mixed  $password - The current password hash
     * 
     * @access public
     */
    public function setCurrentPassword($password) {
        $this->_currentPassword = $password;
    }
    
    /**
     * function getCurrentPassword() - return the current password (hashed)
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-14
     * 
     * @return mixed - The hashed password
     * 
     * @access public
     */
    public function getCurrentPassword() {
        return $this->_currentPassword;
    }
}

<?php
namespace cymapgt\core\application\authentication\UserCredential\abstractclass;

use cymapgt\Exception\UserCredentialException;

/**
 * UserCredentialAuthenticationInterface
 * Interface that will be used by the Login Services
 *
 * @category    
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2014 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
 * 
 * The objectives of the user credential class are:
 *      - Specify methods that log in services must use
 */

interface UserCredentialAuthenticationInterface
{
    /**
     * Specify whether the method uses password
     *                              (set e.g. user log in, lDAP, 2 FACTOR (step 1)
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     *
     * @param bool $flag - if true, is using password
     * 
     * @access public
     */             
    public function setUsePassword($flag);

    /**
     * function getUsePassword() - Return the use password flag
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     *
     * @return bool
     * 
     * @access public
     */             
    public function getUsePassword();
    
    /**
     * Set the user password, and hash it
     *
     * Cyril Ogana <cogana@gmail.com>- 2014-02-13
     *
     * @param bool $password - the user password in raw text
     *
     * @access public
     */             
    public function setPassword($password);
    
    /**
     * Return the hashed user password
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param  $unhashed - if true, return unhashed
     * 
     * @return mixed - the hashed password
     * 
     * @access public
     */
    public function getPassword($unhashed = false);
    
    /**
     * Set whether this service uses multi factor auth
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param bool $flag - if true, is a multi factor auth service
     * 
     * @access public
     */
    public function setMultiFactor($flag);
    
    /**
     * Provide namespace of the multi factor handler service,which has to implement the interface
     * cymapgt\core\application\authentication\abstractclass\UserCredentialAuthenticationMultiFactorInterface
     *                                  
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param string $handler - The namespace of the multi factor handler service
     * 
     * @access public 
     */
    public function setMultiFactorHandler($handler);
    
    /**
     * Return an instance of the multi factor handler service to use ofr this authentication session
     *                                  
     * Cyril Ogana <cogana@gmail.com > - 2014-02-13
     * 
     * @return object
     * 
     * @access public
     */
    public function getMultiFactorHandler();
    
    /**
     * In an array, configure the steps of the multifactor login, passing numeric stage names, types and handler calls
     *                                 
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param Array $stages - The stages of the log in session
     * 
     * @access public
     */
    public function setMultiFactorStages(Array $stages);
    
    /**
     *  return the multi factor stages array
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @return array
     * 
     * @access public
     */
    public function getMultiFactorStages();
    
    /**
     * initialize the service, bootstrap before any processing
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @access public
     */
    public function initialize();
    
    /**
     * authenticate the user after initialization
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @access public
     */
    public function authenticate();
    
    /**
     * set the current username
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-13
     * 
     * @param string $username - The current username
     * 
     * @access public
     */
    public function setCurrentUsername($username);
    
    /**
     * get the current username
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-14
     * 
     * @return string - Return the current username
     * 
     * @access public
     */
    public function getCurrentUsername();
    
    /**
     * set the current password
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-14
     * 
     * @param mixed  $password - The current password hash
     * 
     * @access public
     */
    public function setCurrentPassword($password);
    
    /**
     * return the current password (hashed)
     * 
     * Cyril Ogana <cogana@gmail.com> - 2014-02-14
     * 
     * @return mixed - The hashed password
     * 
     * @access public
     */
    public function getCurrentPassword();
}

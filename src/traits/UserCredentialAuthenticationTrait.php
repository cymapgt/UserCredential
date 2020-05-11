<?php
namespace cymapgt\core\application\authentication\UserCredential\traits;

use cymapgt\Exception\UserCredentialException;

/**
 * Traits for various authentication methods that can be used at various levels
 * of the login stage e.g. Something you know can be password login natively
 * or via LDAP
 *
 * @category    
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2018 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
*/
trait UserCredentialAuthenticationTrait {
    use
        UserCredentialAuthenticationNativeTrait,
        UserCredentialAuthenticationLdapTrait;
    
    abstract public function initialize();  //classes using this trait must declare this method
    abstract public function getCurrentUsername(): string; //classes using this trait must declare this method
    abstract public function getCurrentPassword(): string; //classes using this trait must declare this method
       
    /**
     * Authenticate a users username/password credentials using the requested platform
     * 
     *  Cyril Ogana <cogana@gmail.com> 
     *  2018
     * 
     * @return bool
     * @throws UserCredentialException
     */
    function authenticate(): bool {
        switch ($this->_passwordAuthenticationPlatform) {
            case \USERCREDENTIAL_PASSWORDLOGINPLATFORM_NATIVE:
                return $this->authenticateNative();
            case \USERCREDENTIAL_PASSWORDLOGINPLATFORM_LDAP:
                return $this->authenticateLDAP();
            default:
                throw new UserCredentialException('Unknown native authentication platform requested');
        }
    }
}

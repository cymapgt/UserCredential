<?php
namespace cymapgt\core\application\authentication\UserCredential\traits;

use cymapgt\Exception\UserCredentialException;

/**
 * Traits for varous authentication methods that can be used at various levels
 * of the login stage e.g. Something you know can be password login natively
 * or via LDAP
 *
 * @category    
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2018 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
*/

/**
 * Native password authentication
 */
trait UserCredentialAuthenticationTrait {
    use
        UserCredentialAuthenticationNativeTrait,
        UserCredentialAuthenticationLdapTrait;
            
    function authenticate() {
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

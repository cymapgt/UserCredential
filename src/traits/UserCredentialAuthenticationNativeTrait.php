<?php
namespace cymapgt\core\application\authentication\UserCredential\traits;

/**
 * Trait for authenticating using PHP's native password_hash and password_verify
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
trait UserCredentialAuthenticationNativeTrait {
    function authenticateNative() {
        return \password_verify($this->_inputPassword, $this->_currentPassword);        
    }
}

<?php
namespace cymapgt\core\application\authentication\UserCredential;

use cymapgt\Exception\UserCredentialException;

/**
 * UserCredentialManager
 * Manage the authentication  and password policy process
 *
 * @category    
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2015 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
 * 
 *  @TODO link all configurations
 */

class UserCredentialManager extends abstractclass\UserCredentialAbstract
{
    //Constructor method
    public function __construct($userProfile) {
        parent::__construct($userProfile);
    }
    
    public function getBaseEntropy() {
        return parent::_getBaseEntropy();
    }
    
    public function getBaseEntropyOverride() {
        return parent::_getBaseEntropyOverride();
    }
    
    public function getBasePasswordPolicy() {
        return parent::_getBasePasswordPolicy();
    }
    
    public function getPasswordEntropyDescription() {
        return parent::_getPasswordEntropyDescription();
    }
    
    public function getPasswordLengthDescription() {
        return parent::_getPasswordLengthDescription();
    }
    
    public function getPasswordPolicyDescription() {
        return parent::_getPasswordPolicyDescription();
    }
    
    public function getUdfEntropy() {
        return parent::_getUdfEntropy();
    }
    
    public function getUdfPasswordPolicy(){
        return parent::_getUdfPasswordPolicy();
    }
    
    public function setBaseEntropyOverride($toggle) {
        parent::_setBaseEntropyOverride($toggle);
    }
    
    public function setUdfEntropy($entropyObj) {
        parent::_setUdfEntropy($entropyObj);
    }
    
    public function setUdfPasswordPolicy($entropyObj) {
        parent::_setUdfPasswordPolicy($entropyObj);
    }
    
    public function validateEntropy() {
        return parent::_validateEntropy();
    }
    
    public function validateLength() {
        return parent::_validateLength();
    }
     
    public function validateConsecutiveCharacterRepeat() {
        return parent::_validateConsecutiveCharacterRepeat();
    }
    
    public function validatePolicy() {
        return parent::_validatePolicy();
    }
    
    public function validatePolicyAtChange() {
        return parent::_validatePolicyAtChange();
    }
    
    public function canChangePassword() {
        return parent::_canChangePassword();
    }
}

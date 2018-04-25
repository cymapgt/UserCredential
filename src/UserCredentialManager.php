<?php
namespace cymapgt\core\application\authentication\UserCredential;

use cymapgt\Exception\UserCredentialException;

/**
 * UserCredentialManager
 * Concrete class to Manage the user and password policy process
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
        return $this->_getBaseEntropy();
    }
    
    public function getBaseEntropyOverride() {
        return $this->_getBaseEntropyOverride();
    }
    
    public function getBasePasswordPolicy() {
        return $this->_getBasePasswordPolicy();
    }
    
    public function getPasswordEntropyDescription() {
        return $this->_getPasswordEntropyDescription();
    }
    
    public function getPasswordLengthDescription() {
        return $this->_getPasswordLengthDescription();
    }
    
    public function getPasswordPolicyDescription($policyType) {
        return $this->_getPasswordPolicyDescription($policyType);
    }
    
    public function getUdfEntropy() {
        return $this->_getUdfEntropy();
    }
    
    public function getUdfPasswordPolicy(){
        return $this->_getUdfPasswordPolicy();
    }
    
    public function setBaseEntropyOverride($toggle) {
        $this->_setBaseEntropyOverride($toggle);
    }
    
    public function setUdfEntropy($entropyObj) {
        $this->_setUdfEntropy($entropyObj);
    }
    
    public function setUdfPasswordPolicy($entropyObj) {
        $this->_setUdfPasswordPolicy($entropyObj);
    }
    
    public function validateEntropy() {
        return $this->_validateEntropy();
    }
    
    public function validateEntropyTotp() {
        return $this->_validateEntropyTotp();
    }
    
    public function validateLength() {
        return $this->_validateLength();
    }
     
    public function validateConsecutiveCharacterRepeat() {
        return $this->_validateConsecutiveCharacterRepeat();
    }
    
    public function validateTenancy() {
        return $this->_validateTenancy();
    }
    
    public function validatePolicy() {
        return $this->_validatePolicy();
    }
    
    public function validatePolicyAtChange() {
        return $this->_validatePolicyAtChange();
    }
    
    public function canChangePassword() {
        return $this->_canChangePassword();
    }
}

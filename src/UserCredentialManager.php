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
    
    public function getBaseEntropy(): array {
        return $this->_getBaseEntropy();
    }
    
    public function getBaseEntropyOverride(): bool {
        return $this->_getBaseEntropyOverride();
    }
    
    public function getBasePasswordPolicy(): array {
        return $this->_getBasePasswordPolicy();
    }
    
    public function getPasswordEntropyDescription(): string {
        return $this->_getPasswordEntropyDescription();
    }
    
    public function getPasswordLengthDescription(): string {
        return $this->_getPasswordLengthDescription();
    }
    
    public function getPasswordPolicyDescription(string $policyType): string {
        return $this->_getPasswordPolicyDescription($policyType);
    }
    
    public function getUdfEntropy(): array {
        return $this->_getUdfEntropy();
    }
    
    public function getUdfPasswordPolicy(): array{
        return $this->_getUdfPasswordPolicy();
    }
    
    public function setBaseEntropyOverride(bool $toggle) {
        $this->_setBaseEntropyOverride($toggle);
    }
    
    public function setUdfEntropy(array $entropyObj) {
        $this->_setUdfEntropy($entropyObj);
    }
    
    public function setUdfPasswordPolicy(array $entropyObj) {
        $this->_setUdfPasswordPolicy($entropyObj);
    }
    
    public function validateEntropy(): bool {
        return $this->_validateEntropy();
    }
    
    public function validateEntropyTotp(): bool {
        return $this->_validateEntropyTotp();
    }
    
    public function validateLength(): bool {
        return $this->_validateLength();
    }
     
    public function validateConsecutiveCharacterRepeat(): bool {
        return $this->_validateConsecutiveCharacterRepeat();
    }
    
    public function validateTenancy(): bool {
        return $this->_validateTenancy();
    }
    
    public function validatePolicy(): bool {
        return $this->_validatePolicy();
    }
    
    public function validatePolicyAtChange(): bool {
        return $this->_validatePolicyAtChange();
    }
    
    public function canChangePassword(): bool {
        return $this->_canChangePassword();
    }
}

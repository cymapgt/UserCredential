<?php
namespace cymapgt\core\application\authentication\UserCredential\traits;

use cymapgt\core\application\authentication\UserCredential\abstractclass\MultiotpWrapper;
use cymapgt\Exception\UserCredentialException;

/**
*  Trait for authenticating using LDAP
 *
 * @category    
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2018 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
*/
trait UserCredentialAuthenticationLdapTrait {
    protected $ldapAuthenticationHandler = null; //container for LDAP handler e.g. MultiOTP, FreeDSX
    
    abstract public function initialize();  //classes using this trait must declare this method
    abstract public function getCurrentUsername(); //classes using this trait must declare this method
    abstract public function getCurrentPassword(); //classes using htis trait must declare this method
 
    
    /**
     * Authenticate credentials provided by user against a LDAP server
     * 
     *  Cyril Ogana <cogana@gmail.com> 
     *  2018
     * s
     * @return bool
     * @throws UserCredentialException
     */      
    protected function authenticateLDAP() {
        //initialize the LDAP parameters as required by ldap handler
        $this->initializeLdap();
        
        //authenticate via LDAP
        $ldapAuthenticationHandler = $this->ldapAuthenticationHandler;
        
        return $ldapAuthenticationHandler->CheckLdapAuthentication();
    }
    
    /**
     *  Check that the initialization parameters array for LDAP authentication is enriched with the
     *  required keys
     * 
     *  Cyril Ogana <cogana@gmail.com> 
     *  2018
     * 
     * @throws UserCredentialException
     */
    public function initializeLdap() {
        //initialize from parent
        $this->initialize();
        
        //validate ldap settings
        $ldapSettings = $this->_passwordAuthenticationPlatformSettings;

        if(
            !(array_key_exists('ldap_account_suffix', $ldapSettings))
            ||!(array_key_exists('ad_password', $ldapSettings))
            || !(array_key_exists('ad_username', $ldapSettings))
            || !(array_key_exists('base_dn', $ldapSettings))
            || !(array_key_exists('cn_identifier', $ldapSettings))
            || !(array_key_exists('domain_controllers', $ldapSettings))
            || !(array_key_exists('group_attribute', $ldapSettings))
            || !(array_key_exists('group_cn_identifier', $ldapSettings))
            || !(array_key_exists('ldap_server_type', $ldapSettings))
            || !(array_key_exists('network_timeout', $ldapSettings))
            || !(array_key_exists('port', $ldapSettings))
            || !(array_key_exists('recursive_groups', $ldapSettings))
            || !(array_key_exists('time_limit', $ldapSettings))
            || !(array_key_exists('use_ssl', $ldapSettings))
            || !(array_key_exists('cache_support', $ldapSettings))
            || !(array_key_exists('cache_folder', $ldapSettings))
            || !(array_key_exists('expired_password_valid', $ldapSettings))
        ) {
           throw new UserCredentialException("The LDAP feature of the usercredential login service is not initialized with all parameters", 2000);
        }
        
        //inject settings to the ldap handler
        $this->_passwordAuthenticationPlatformSettings = $ldapSettings;       
        $this->initializeLdapAuthenticationHandler();
    }
    
    /**
     *  Instantiate the LDAP handler and inject appropriate settings into it
     * 
     *  Cyril Ogana <cogana@gmail.com> 
     *  2018
     */
    protected function initializeLdapAuthenticationHandler() {
        $ldapSettings = $this->_passwordAuthenticationPlatformSettings;
        $ldapAuthenticationHandler = new MultiotpWrapper();
        
        $ldapAuthenticationHandler->SetLdapServerPassword($this->getCurrentPassword());
        $ldapAuthenticationHandler->SetLdapBindDn($this->getCurrentUsername());
        $ldapAuthenticationHandler->SetLdapAccountSuffix($ldapSettings['ldap_account_suffix']);
        $ldapAuthenticationHandler->SetLdapBaseDn($ldapSettings['base_dn']);
        $ldapAuthenticationHandler->SetLdapCnIdentifier($ldapSettings['cn_identifier']);
        $ldapAuthenticationHandler->SetLdapDomainControllers($ldapSettings['domain_controllers']);
        $ldapAuthenticationHandler->SetLdapGroupAttribute($ldapSettings['group_attribute']);
        $ldapAuthenticationHandler->SetLdapGroupCnIdentifier($ldapSettings['group_cn_identifier']);
        $ldapAuthenticationHandler->SetLdapServerType($ldapSettings['ldap_server_type']);
        $ldapAuthenticationHandler->SetLdapNetworkTimeout($ldapSettings['network_timeout']);
        $ldapAuthenticationHandler->SetLdapPort($ldapSettings['port']);
        $ldapAuthenticationHandler->SetLdapRecursiveGroups($ldapSettings['recursive_groups']);
        $ldapAuthenticationHandler->SetLdapTimeLimit($ldapSettings['time_limit']);
        $ldapAuthenticationHandler->SetLdapSsl($ldapSettings['use_ssl']);
        $ldapAuthenticationHandler->SetLdapCacheOn($ldapSettings['cache_support']);
        $ldapAuthenticationHandler->SetLdapCacheFolder($ldapSettings['cache_folder']);
        $ldapAuthenticationHandler->SetLdapExpiredPasswordValid($ldapSettings['expired_password_valid']);
        
        $this->ldapAuthenticationHandler = $ldapAuthenticationHandler;
    }
}

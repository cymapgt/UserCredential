<?php
/**
 * Execute the FreeDSX LDAP Server in the background
 */
chdir(dirname(__FILE__));
require_once("bootstrap.php");

use FreeDSx\Ldap;

//verify ldap port is open
$ldapConnection = @fsockopen('localhost', 33389);

if (is_resource($ldapConnection)) {
    throw new \Exception("There is a service already running on port 33389. Cannot setup FreeDsx LDAP Server");
}

$ldapServer = new Ldap\LdapServer([
    //we shall not require authentication
    'require_authentication' => false,
    
    //allow anonymous connections
    'allow_anonymous' => true,
    
    'request_handler' => \LdapRequestHandler::class,
    //'dse_alt_server' => 'dc2.local',
    'port' => 33389,
]);

$ldapServer->run();

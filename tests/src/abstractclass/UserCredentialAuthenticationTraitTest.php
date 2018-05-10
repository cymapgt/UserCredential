<?php
namespace cymapgt\core\application\authentication\UserCredential\abstractclass;

use FreeDSx\Ldap;
use cymapgt\core\application\authentication\UserCredential\services\UserCredentialPasswordLoginService;


/**
 *  Unit test for authentication traits
 * 
 */
class UserCredentialAuthenticationTraitTest extends \PHPUnit\Framework\TestCase
{
    /**
     *  @var LdapServer
     */
    protected $ldapServer;
    
    /**
     * @var UserCredentialPasswordLoginService
     */
    protected $object;
    
    protected function setUp() {
        $userCredentialPasswordLoginService = new UserCredentialPasswordLoginService();
        
        //instantiate password login service
        $username = 'lantana';
        $password = 123456;
        $passwordHashed = '$2y$10$Fc0C2OCH1QfGzeNedX7SfeIFOSovx45sVzPOaBhcNUBGj92nIBAtW';

        //username of authenticating user
        $userCredentialPasswordLoginService->setCurrentUserName($username);
        
        //password that is stored in the DB
        $userCredentialPasswordLoginService->setCurrentPassword($passwordHashed);
        
        //password input by the user in the login form / API
        $userCredentialPasswordLoginService->setPassword($password);
        
        $this->object = $userCredentialPasswordLoginService;
        
        
        //verify ldap port is open
        /*$ldapConnection = @fsockopen('localhost', 33389);
        
        if (is_resource($ldapConnection)) {
            throw new \Exception("There is a service already running on port 33389. Cannot setup FreeDsx LDAP Server");
        }
        
        $ldapServer = new Ldap\LdapServer([
            'dse_alt_server' => 'dc2.local',
            'port' => 33389,
        ]);
        
        $this->ldapServer = $ldapServer;
        $this->ldapServer->run();*/
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\abstractclass\UserCredentialAuthenticationTrait::authenticate
     */
    public function testAuthenticationNative() {
        $authenticationPlatform = \USERCREDENTIAL_PASSWORDLOGINPLATFORM_NATIVE;
        $this->object->setAuthenticationPlatform($authenticationPlatform);
        
        $this->assertEquals(true, $this->object->authenticate());
    }
}

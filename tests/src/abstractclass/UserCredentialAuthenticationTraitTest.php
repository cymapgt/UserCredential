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
        
        chdir(dirname(__FILE__));
        $ldapServerPath = "../../files/FreeDsxLdapServer.php";
        $ldapServerPathFq = realpath($ldapServerPath);
        \exec("php \"$ldapServerPathFq\" > /dev/null &");
        //sleep(10000);
        
        $ldap = new Ldap\LdapClient([
            # The base_dn as the default for all searches (if not explicitly defined)
            'base_dn' => 'cn=read-only-admin,dc=example,dc=com',
            # An array of servers to try to connect to
            'servers' => ['ldap.forumsys.com'],
        ]);
        
        try {
            $ldap->bind('uid=gauss,dc=example,dc=com', 'password');
            die(print_r($ldap));
        } catch (BindException $e) {
           echo sprintf('Error (%s): %s', $e->getCode(), $e->getMessage());
           exit;
        }        
    }
    
    protected function tearDown() {
        \exec("fuser -k 33389/tcp  > /dev/null &");
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\abstractclass\UserCredentialAuthenticationTrait::authenticate
     */
    public function testAuthenticationNative() {
        $authenticationPlatform = \USERCREDENTIAL_PASSWORDLOGINPLATFORM_NATIVE;
        $this->object->setAuthenticationPlatform($authenticationPlatform);
        
        $this->assertEquals(true, $this->object->authenticate());
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\abstractclass\UserCredentialAuthenticationTrait::authenticate
     */
    public function testAuthenticationLdap() {
        $authenticationPlatform = \USERCREDENTIAL_PASSWORDLOGINPLATFORM_LDAP;
        $this->object->setAuthenticationPlatform($authenticationPlatform);
        
        
    }
}

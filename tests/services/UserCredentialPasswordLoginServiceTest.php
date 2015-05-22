<?php

namespace cymapgt\core\application\authentication\UserCredential\services;

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-05-18 at 14:28:58.
 */
class UserCredentialPasswordLoginServiceTest extends \PHPUnit_Framework_TestCase {

    /**
     * @var UserCredentialPasswordLoginService
     */
    protected $object;
    protected $password;

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp() {
        $this->object   = new UserCredentialPasswordLoginService;
        $this->password = \password_hash('123456', \PASSWORD_DEFAULT);
    }

    /**
     * Tears down the fixture, for example, closes a network connection.
     * This method is called after a test is executed.
     */
    protected function tearDown() {
        
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\services\UserCredentialPasswordLoginService::initialize
     */
    public function testInitialize() {
        $this->object->setCurrentUserName('rhossis');
        $this->object->setCurrentPassword($this->password);
        $this->object->setPassword('123456');
        $this->assertEquals(null, $this->object->initialize());
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\services\UserCredentialPasswordLoginService::initialize
     */
    public function testInitializeException() {
        $this->setExpectedException('cymapgt\Exception\UserCredentialException', 'The usercredential login service is not initialized with all parameters');
        $this->object->initialize();
    }    

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\services\UserCredentialPasswordLoginService::authenticate
     */
    public function testAuthenticate() {
        $this->object->setCurrentUserName('rhossis');
        $this->object->setCurrentPassword($this->password);
        $this->object->setPassword('123456');
        $this->assertEquals(true, $this->object->authenticate());
        $this->object->setPassword('12345');
        $this->assertEquals(false, $this->object->authenticate());
)
    }
}

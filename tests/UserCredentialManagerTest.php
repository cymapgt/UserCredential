<?php
namespace cymapgt\core\application\authentication\UserCredential;

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-05-17 at 22:36:01.
 */
class UserCredentialManagerTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var UserCredentialManager
     */
    protected $object;

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp()
    {
        $userProfile = array("username"=>"c.ogana",
                          "password"=>"m&$1eLe6Ke()",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                            \password_hash('abc', \PASSWORD_DEFAULT),
                            \password_hash('def', \PASSWORD_DEFAULT),
                            \password_hash('ghi', \PASSWORD_DEFAULT),
                            \password_hash('jkl', \PASSWORD_DEFAULT),
                            \password_hash('mno', \PASSWORD_DEFAULT),
                            \password_hash('pqr', \PASSWORD_DEFAULT),
                            \password_hash('stu', \PASSWORD_DEFAULT),
                            \password_hash('vwx', \PASSWORD_DEFAULT),
                            \password_hash('xyz', \PASSWORD_DEFAULT)
                          ), //in reality, these are bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime('2014-05-04'),
                              'last_login_attempt_datetime' => new \DateTime('2014-05-16 23:45:10')
                          ),
                          "totpinfo"=>array(
                              'enc_key' => 'iamanenkkeyandiamoftherequiredlength:)'
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile);
    }

    /**
     * Tears down the fixture, for example, closes a network connection.
     * This method is called after a test is executed.
     */
    protected function tearDown()
    {
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::getBaseEntropy
     */
    public function testGetBaseEntropy()
    {
        $baseEntropy = $this->object->getBaseEntropy();
        $this->assertInternalType('array', $baseEntropy);
        $this->assertEquals(9, count($baseEntropy));
        $this->assertEquals('min_pass_len', key($baseEntropy));
        next($baseEntropy);
        $this->assertEquals('max_consecutive_chars', key($baseEntropy));
        next($baseEntropy);
        $this->assertEquals('max_consecutive_chars_of_same_class', key($baseEntropy));
        next($baseEntropy);
        $this->assertEquals('uppercase', key($baseEntropy));
        next($baseEntropy);        
        $this->assertEquals('numeric', key($baseEntropy));
        next($baseEntropy);        
        $this->assertEquals('lowercase', key($baseEntropy));
        next($baseEntropy);        
        $this->assertEquals('special', key($baseEntropy));
        next($baseEntropy);
        $this->assertEquals('multi_factor_on', key($baseEntropy));
        next($baseEntropy);
        $this->assertEquals('multi_factor_enc_key_length', key($baseEntropy));
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::getBaseEntropyOverride
     */
    public function testGetBaseEntropyOverride()
    {
        $baseEntropyOverride = $this->object->getBaseEntropyOverride();
        $this->assertInternalType('bool', $baseEntropyOverride);
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::getBasePasswordPolicy
     */
    public function testGetBasePasswordPolicy()
    {
        $basePasswordPolicy = $this->object->getBasePasswordPolicy();
        $this->assertInternalType('array', $basePasswordPolicy);
        $this->assertEquals(4, count($basePasswordPolicy));
        $this->assertEquals('illegal_attempts_limit', key($basePasswordPolicy));
        next($basePasswordPolicy);
        $this->assertEquals('password_reset_frequency', key($basePasswordPolicy));
        next($basePasswordPolicy);
        $this->assertEquals('password_repeat_minimum', key($basePasswordPolicy));
        next($basePasswordPolicy);
        $this->assertEquals('illegal_attempts_penalty_seconds', key($basePasswordPolicy));
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::getUdfEntropy
     */
    public function testGetUdfEntropy()
    {
        $udfEntropy = $this->object->getUdfEntropy();
        $this->assertInternalType('array', $udfEntropy);
        $this->assertEquals(7, count($udfEntropy));
        $this->assertEquals('min_pass_len', key($udfEntropy));
        next($udfEntropy);
        $this->assertEquals('max_consecutive_chars', key($udfEntropy));
        next($udfEntropy);
        $this->assertEquals('max_consecutive_chars_of_same_class',key($udfEntropy));
        next($udfEntropy);
        $this->assertEquals('uppercase', key($udfEntropy));
        next($udfEntropy);        
        $this->assertEquals('lowercase', key($udfEntropy));
        next($udfEntropy);        
        $this->assertEquals('numeric', key($udfEntropy));
        next($udfEntropy);        
        $this->assertEquals('special', key($udfEntropy));
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::getUdfPasswordPolicy
     */
    public function testGetUdfPasswordPolicy()
    {
        $udfPasswordPolicy = $this->object->getBasePasswordPolicy();
        $this->assertInternalType('array', $udfPasswordPolicy);
        $this->assertEquals(4, count($udfPasswordPolicy));
        $this->assertEquals('illegal_attempts_limit', key($udfPasswordPolicy));
        next($udfPasswordPolicy);
        $this->assertEquals('password_reset_frequency', key($udfPasswordPolicy));
        next($udfPasswordPolicy);
        $this->assertEquals('password_repeat_minimum', key($udfPasswordPolicy));
        next($udfPasswordPolicy);
        $this->assertEquals('illegal_attempts_penalty_seconds', key($udfPasswordPolicy));
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::setBaseEntropyOverride
     */
    public function testSetBaseEntropyOverride()
    {
        $this->object->setBaseEntropyOverride(true);
        $baseEntropyOverride = $this->object->getBaseEntropyOverride();
        $this->assertInternalType('bool', $baseEntropyOverride);
        $this->assertEquals(true, $baseEntropyOverride);
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateEntropy
     */
    public function testValidateEntropy()
    {
        $this->assertInternalType('bool', $this->object->validateEntropy());        
        $this->assertEquals(true, $this->object->validateEntropy());
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateEntropy
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage The password does not meet the minimum entropy.
     */
    public function testValidateEntropyException() {
        $userProfileWeak = array("username"=>"c.ogana",
                          "password"=>"weak_password",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(),
                          "policyinfo"=>array(),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfileWeak);
        $this->object->validateEntropy();
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateLength
     */
    public function testValidateLength() {
        $this->assertInternalType('bool', $this->object->validateLength());
        $this->assertEquals(true, $this->object->validateLength());
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateConsecutiveCharacterRepeat()
     */
    public function testValidateConsecutiveCharacterRepeat() {
        $this->assertInternalType('bool', $this->object->validateConsecutiveCharacterRepeat());
        $this->assertEquals(true, $this->object->validateConsecutiveCharacterRepeat());
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateLength
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage The password does not meet required length.
     */
    public function testValidateLengthException() {
        $userProfileWeak = array("username"=>"c.ogana",
                          "password"=>"tinypw",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(),
                          "policyinfo"=>array(),            
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfileWeak);
        $this->object->validateLength();
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateConsecutiveCharacterRepeat()
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage The password violates policy about consecutive character repetitions.
     */ 
    public function testValidateConsecutiveCharacterRepeatException() {
        //here we repeat 2 characters
        $userProfileAlmostWeak = array("username"=>"c.ogana",
                          "password"=>"%stron9Pa55sButRepetition!sBaD2015",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(),
                          "policyinfo"=>array(),            
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfileAlmostWeak);
        $this->assertTrue($this->object->validateConsecutiveCharacterRepeat());
        
        //here we repeat 3 characters, and expect an exception as per base entropy
        $userProfileWeak = array("username"=>"c.ogana",
                          "password"=>"%stron9Pa555sButRepetition!sBaD2015",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(),
                          "policyinfo"=>array(),            
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfileWeak); 
        $this->object->validateConsecutiveCharacterRepeat();
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateConsecutiveCharacterRepeat()
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage The password violates policy about consecutive repetition of characters of the same class.
     */ 
    public function testValidateConsecutiveCharacterClassRepeatException() {
        //here we repeat 2 characters
        $userProfileAlmostWeak = array("username"=>"c.ogana",
                          "password"=>"%stron9Pa55sButRepetition!sBaD2015",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(),
                          "policyinfo"=>array(),            
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfileAlmostWeak);
        $this->assertTrue($this->object->validateConsecutiveCharacterRepeat());
        
        //here we repeat 3 characters, and expect an exception as per base entropy
        $userProfileWeak = array("username"=>"c.ogana",
                          "password"=>"%stron9Pa55sButClassrepetition!sBaD2015",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(),
                          "policyinfo"=>array(),            
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfileWeak); 
        $this->object->validateConsecutiveCharacterRepeat();
    }    
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validatePolicy
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage The account has exceeded login attempts and is locked.
     */
    public function testValidatePolicyLoginAttemptSuspendedException() {
        $userProfileWeak = array("username"=>"c.ogana",
                          "password"=>"tinypw",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(),
                          "policyinfo"=>array('failed_attempt_count' => 4),            
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_AUTHFAILED);        
        $this->object = new UserCredentialManager($userProfileWeak);
        $this->object->validatePolicy();       
    } 
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validatePolicy
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage The password has expired and must be changed
     */
    public function testValidatePolicyPasswordExpiredException() {
        $userProfile = array("username"=>"c.ogana",
                          "password"=>"m&$1eLe6Ke()",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                          ), //in reality, these are bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime('2014-03-01'),
                              'last_login_attempt_datetime' => new \DateTime('2014-03-01 23:45:10')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile);
        $this->object->validatePolicy();
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validatePolicy
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage Password cannot contain username or any of your names
     */
    public function testValidateEntropyPasswordContainsUsernameException() {
        $userProfile = array("username"=>"c.ogana",
                          "password"=>"1CyriL",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                          ), //in reality, these are bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime('2015-05-01'),
                              'last_login_attempt_datetime' => new \DateTime('2015-03-01 23:45:10')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile);
        $this->object->validateEntropy();
    }

    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validatePolicy
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage Password cannot contain username or any of your names
     */
    public function testValidateEntropyPasswordContainsReverseNameException() {
        $userProfile = array("username"=>"c.ogana",
                          "password"=>"1LiryC!",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                          ), //in reality, these are bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime('2015-05-01'),
                              'last_login_attempt_datetime' => new \DateTime('2015-03-01 23:45:10')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile);
        $this->object->validateEntropy();
    }    
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validatePolicy
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage Password cannot contain username or any of your names
     */
    public function testValidateEntropyPasswordContainsReverseUsernameException() {        
        $userProfile1 = array("username"=>"c.ogana",
                          "password"=>"anago.c",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                          ), //in reality, these are bcrypt hashes
                          "policyinfo"=>array (
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime('2015-05-01'),
                              'last_login_attempt_datetime' => new \DateTime('2015-03-01 23:45:10')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile1);
        $this->object->validateEntropy();        
    }    
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validatePolicyAtChange
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage User cannot repeat any of their 
     */
    public function testValidatePolicyPasswordRepeatException() {
        $userProfile = array("username"=>"c.ogana",
                          "password"=>"mno",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                            \password_hash('abc', \PASSWORD_DEFAULT),
                            \password_hash('def', \PASSWORD_DEFAULT),
                            \password_hash('ghi', \PASSWORD_DEFAULT),
                            \password_hash('jkl', \PASSWORD_DEFAULT),
                            \password_hash('mno', \PASSWORD_DEFAULT),
                            \password_hash('pqr', \PASSWORD_DEFAULT),
                            \password_hash('stu', \PASSWORD_DEFAULT),
                            \password_hash('vwx', \PASSWORD_DEFAULT),
                            \password_hash('xyz', \PASSWORD_DEFAULT)
                          ), //in reality, these are already bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime('2014-05-04'),
                              'last_login_attempt_datetime' => new \DateTime('2014-03-01 23:45:10')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile); 
        $this->object->validatePolicyAtChange();
    }
    
    
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::canChangePassword
     */
    public function testValidatePolicyCanChangePassword() {
        $userProfile = array("username"=>"c.ogana",
                          "password"=>"mno",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                            \password_hash('abc', \PASSWORD_DEFAULT),
                            \password_hash('def', \PASSWORD_DEFAULT),
                            \password_hash('ghi', \PASSWORD_DEFAULT),
                            \password_hash('jkl', \PASSWORD_DEFAULT),
                            \password_hash('mno', \PASSWORD_DEFAULT),
                            \password_hash('pqr', \PASSWORD_DEFAULT),
                            \password_hash('stu', \PASSWORD_DEFAULT),
                            \password_hash('vwx', \PASSWORD_DEFAULT),
                            \password_hash('xyz', \PASSWORD_DEFAULT)
                          ), //in reality, these are already bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime(),
                              'last_login_attempt_datetime' => new \DateTime('2014-03-01 23:45:10')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile); 
        $canChangePassword = $this->object->canChangePassword();
        $this->assertInternalType('bool', $canChangePassword);
        $this->assertEquals(false, $canChangePassword);
    }
    
    /**
     * @covers \cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateTenancy
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage Tenancy problem with your account. Please contact your Administrator
     */ 
    public function testValidateTenancyException() {
        $userProfile = array("username"=>"c.ogana",
                          "password"=>"mno",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                            \password_hash('abc', \PASSWORD_DEFAULT),
                            \password_hash('def', \PASSWORD_DEFAULT),
                            \password_hash('ghi', \PASSWORD_DEFAULT),
                            \password_hash('jkl', \PASSWORD_DEFAULT),
                            \password_hash('mno', \PASSWORD_DEFAULT),
                            \password_hash('pqr', \PASSWORD_DEFAULT),
                            \password_hash('stu', \PASSWORD_DEFAULT),
                            \password_hash('vwx', \PASSWORD_DEFAULT),
                            \password_hash('xyz', \PASSWORD_DEFAULT)
                          ), //in reality, these are already bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime(),
                              'last_login_attempt_datetime' => new \DateTime('2014-03-01 23:45:10'),
                              'tenancy_expiry' => new \DateTime('2017-12-31 00:00:00')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile); 
        $this->object->validateTenancy();
    }
    
    /**
     * @covers \cymapgt\core\application\authentication\UserCredential\UserCredentialManager::validateTenancy
     */
    public function testValidateTenancy() {
        $userProfile = array("username"=>"c.ogana",
                          "password"=>"mno",
                          "fullname"=>"Cyril Ogana",
                          "passhash"=>"tiger",
                          "passhist"=>array(
                            \password_hash('abc', \PASSWORD_DEFAULT),
                            \password_hash('def', \PASSWORD_DEFAULT),
                            \password_hash('ghi', \PASSWORD_DEFAULT),
                            \password_hash('jkl', \PASSWORD_DEFAULT),
                            \password_hash('mno', \PASSWORD_DEFAULT),
                            \password_hash('pqr', \PASSWORD_DEFAULT),
                            \password_hash('stu', \PASSWORD_DEFAULT),
                            \password_hash('vwx', \PASSWORD_DEFAULT),
                            \password_hash('xyz', \PASSWORD_DEFAULT)
                          ), //in reality, these are already bcrypt hashes
                          "policyinfo"=>array(
                              'failed_attempt_count' => 0,
                              'password_last_changed_datetime' => new \DateTime(),
                              'last_login_attempt_datetime' => new \DateTime('2014-03-01 23:45:10'),
                              'tenancy_expiry' => new \DateTime('tomorrow')
                          ),
                          "account_state"=>\USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN);        
        $this->object = new UserCredentialManager($userProfile); 
        $tenancyIsValid = $this->object->validateTenancy();
        $this->assertEquals(true, $tenancyIsValid);
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential\UserCredentialManager::passwordStrength
     */    
    public function testPasswordStrength() {
        $passwordString = 'MySecretPassword';
        $this->assertEquals(30, UserCredentialManager::passwordStrength($passwordString));
        $this->assertEquals(59, UserCredentialManager::passwordStrength($passwordString, \PHPASS_PASSWORDSTRENGTHADAPTER_WOLFRAM));
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredential::__construct
     * @expectedException \cymapgt\Exception\UserCredentialException
     * @expectedExceptionMessage Multi factor auth is flagged on, but the encryption key length is not properly initialized!
     */
    public function testSetMultiFactorKeyLengthExceptionIfOn() {
        $entropyObj = Array
        (
            'min_pass_len' => 8,
            'max_consecutive_chars' => 2,
            'max_consecutive_chars_of_same_class' => 10,
            'uppercase' => Array
                (
                    'toggle' => true,
                    'min_len' => 2
                ),
            'numeric' => Array
                (
                    'toggle' => true,
                    'min_len' => 1
                ),
            'lowercase' => Array
                (
                    'toggle' => true,
                    'min_len' => 2
                ),

            'special' => Array
                (
                    'toggle' => true,
                    'min_len' => 1
                ),

            'multi_factor_on' => true,
            'multi_factor_enc_key_length' => 15
        );        
        
        $this->object->setUdfEntropy($entropyObj);
    }
    
    /**
     * @covers  cymapgt\core\application\authentication\UserCredential::generateRandomKey
     */
    public function testGenerateRandomKey() {
        $this->assertEquals(16, strlen(UserCredentialManager::generateRandomKey(16)));
       
        $keyLength = 24;
        
        $entropyObj = Array
        (
            'min_pass_len' => 8,
            'max_consecutive_chars' => 2,
            'max_consecutive_chars_of_same_class' => 10,
            'uppercase' => Array
                (
                    'toggle' => true,
                    'min_len' => 2
                ),
            'numeric' => Array
                (
                    'toggle' => true,
                    'min_len' => 1
                ),
            'lowercase' => Array
                (
                    'toggle' => true,
                    'min_len' => 2
                ),

            'special' => Array
                (
                    'toggle' => true,
                    'min_len' => 1
                ),

            'multi_factor_on' => true,
            'multi_factor_enc_key_length' => $keyLength
        );         
        
        $this->assertEquals($keyLength, strlen(UserCredentialManager::generateRandomKey($keyLength)));        
    }
    
    /**
     * @covers  cymapgt\core\application\authentication\UserCredential::validateEntropyTotp
     */
    public function testValidateEntropyTotp() {
        $this->assertInternalType('bool', $this->object->validateEntropyTotp());        
        $this->assertEquals(true, $this->object->validateEntropyTotp());
    }
    
    /**
     * @covers cymapgt\core\application\authentication\UserCredeintial::generateToken
     */
    public function testGenerateToken() {
        $this->assertEquals(6, strlen(UserCredentialManager::generateToken('rhossis', 'iAmAsTrInGeNcRyPtIoNkEyYo!:)')));
    }
}

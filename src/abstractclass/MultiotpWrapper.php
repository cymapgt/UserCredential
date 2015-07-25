<?php
namespace cymapgt\core\application\authentication\UserCredential\abstractclass;

use cymapgt\Exception\UserCredentialException;

/**
 * Wrapper for Multiotp library to enhance the TOTP functionality
 * TODO: delegate work of authentication to Multiotp when they release the SOAP web service
 *
 * @category    security
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2015 Cymap
 * @author      Cyril Ogana <cogana@gmail.com>
 * @abstract
 * 
 *      - See http://www.multiotp.net
 */
class MultiotpWrapper extends \Multiotp
{
    /**
     * Generate SMS token for systems handling authentication task of user management
     * outside of multiotp infrastructure
    * Cyril Ogana <cogana@gmail.com>
     * 2015-07-25
     * 
     * @param string user - The username
     * 
     * @return int
     * @access public
     */
    public function GenerateSmsToken($userName) {
        $nowEpoch = time();
        $smsNowSteps = $nowEpoch;
        $smsDigits = 6;
        $userTokenSeed = substr(md5(date("YmdHis").mt_rand(100000,999999)),0,20).substr(md5(mt_rand(100000,999999).date("YmdHis")),0,20);
        $smsSeedBin = hex2bin(md5('sMs'.$this->GetEncryptionKey().$userTokenSeed.$userName.$nowEpoch));
        $smsToken = $this->GenerateOathHotp($smsSeedBin,$smsNowSteps,$smsDigits);
        $smsNiceToken = $this->ConvertToNiceToken($smsToken);
        return $smsNiceToken;
    }
}

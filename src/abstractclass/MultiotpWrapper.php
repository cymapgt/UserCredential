<?php
namespace cymapgt\core\application\authentication\UserCredential\abstractclass;

use cymapgt\Exception\UserCredentialException;

/**
 * Wrapper for Multiotp library to enhance the TOTP functionality
 * TODO: delegate work of authentication to Multiotp when they release the SOAP web service
 *
 * @category    security
 * @package     cymapgt.core.application.authentication.UserCredential
 * @copyright   Copyright (c) 2016 Cymap
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
    public function GenerateSmsToken($user = '') {
        $userName = $user;
        $nowEpoch = time();
        $smsNowSteps = $nowEpoch;
        $smsDigits = 6;
        $userTokenSeed = substr(md5(date("YmdHis").mt_rand(100000,999999)),0,20).substr(md5(mt_rand(100000,999999).date("YmdHis")),0,20);
        $smsSeedBin = hex2bin(md5('sMs'.$this->GetEncryptionKey().$userTokenSeed.$userName.$nowEpoch));
        $smsToken = $this->GenerateOathHotp($smsSeedBin,$smsNowSteps,$smsDigits);
        $smsNiceToken = $this->ConvertToNiceToken($smsToken);
        return $smsNiceToken;
    }
    
    
   /**
     * @brief   Check the token of the actual user and give the result, with resync options.
     *
     * @param   string  $input                 Token to check
     * @param   string  $input_sync_param      Second token to check for resync
     * @param   string  $display_status        Display the status bar
     * @param   string  $ignore_lock           Ignore the fact that the user is locked
     * @param   string  $resync_enc_pass       Resynchronization with an encrypted password
     * @param   string  $no_server_check       Ignore any server(s) (if any)  to do the check
     * @param   string  $self_register_serial  Serial number of the self registered hardware token
     *                                          (if any, and not combined as a prefix of the input)
     * @param   string  $hardware_tokens_list  Comma separated list of hardware tokens also attributed
     *
     * @return  int                            Error code (0: successful authentication, 1n: info, >=20: error)
     *
     * @author  Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
     * @version 4.3.2.2
     * @date    2015-06-09
     * @since   2010-06-07
     */
    public function CheckToken (
        $input = '',
        $input_sync_param = '',
        $display_status = FALSE,
        $ignore_lock = FALSE,
        $resync_enc_pass = FALSE,
        $no_server_check = FALSE,
        $self_register_serial = '',
        $hardware_tokens_list = ''
    ) {
        $this->SetLastClearOtpValue();
        $calculated_token = '';
        $now_epoch = time();
        $input_sync = $input_sync_param;
        
        // 4.3.2.2
        // As external passwords are now supported,
        // we cannot trim or remove the minus anymore.
        // We disabled trim(str_replace('-','',$input))
        $input_to_check = $input;
        $real_user = $this->GetUser();
        
        // We don't accept any input without at least 3 characters (like 'sms')
        if (strlen($input_to_check) < 3) {
            $input_to_check = "! <3 digits";
        }

        // TODO check multiple tokens (loop)
        $pin               = $this->GetUserPin();
        $need_prefix       = (1 == $this->GetUserPrefixPin());
        $last_event        = $this->GetUserTokenLastEvent();
        $last_login        = $this->GetUserTokenLastLogin();
        $digits            = $this->GetUserTokenNumberOfDigits();
        $error_counter     = $this->GetUserErrorCounter();
        $time_window       = $this->GetMaxTimeWindow();
        $event_window      = $this->GetMaxEventWindow();
        $time_sync_window  = $this->GetMaxTimeResyncWindow();
        $event_sync_window = $this->GetMaxEventResyncWindow();
        
        $seed              = $this->GetTokenSeed();
        $seed_bin          = hex2bin($seed);
        
        $delta_time        = $this->GetTokenDeltaTime();
        $interval          = $this->GetTokenTimeInterval();
        $token_algo_suite  = $this->GetTokenAlgoSuite();
        
        if (0 >= $interval) {
            $interval = 1;
        }

        $now_steps         = intval($now_epoch / $interval);

        $step_window       = intval($time_window / $interval);
        $step_sync_window  = intval($time_sync_window / $interval);
        $last_login_step   = intval($last_login / $interval);
        $delta_step        = $delta_time / $interval;

        $prefix_pin = ($need_prefix?$pin:'');

        // 4.3.2.2
        // Check if resynchronisation can be done automatically
        $needed_space_pos = (strlen($input_to_check)-$digits-1);
        if (('' == $input_sync) && ($needed_space_pos >= $digits) && (($needed_space_pos === strrpos($input_to_check, ' ')) || (($needed_space_pos-strlen($prefix_pin)) === strrpos($input_to_check, ' '))) && ($this->IsAutoResync())) {
            if (($need_prefix) && ($this->IsUserRequestLdapPasswordEnabled())) {
                $ldap_to_check = substr($input_to_check, 0, - ($digits + 1 + $digits));
                if ('' != $ldap_to_check) {
                    if ($this->CheckUserLdapPassword($this->GetUserSynchronizedDn(), $ldap_to_check)) {
                        $input_sync = substr($input_to_check, -$digits);
                        $input_to_check = substr($input_to_check, 0, - ($digits + 1));
                    }
                }
            } elseif ($prefix_pin == substr($input_to_check, 0, strlen($prefix_pin))) {
                $separator_pos = strrpos($input_to_check, ' ');
                $input_sync = str_replace($prefix_pin, '', substr($input_to_check, $separator_pos+1));
                $input_to_check = substr($input_to_check, 0, $separator_pos);
            }
        }

        $result = 99;
        
        switch (strtolower($this->GetUserAlgorithm())) {
            case 'motp':
                if (('' == $input_sync) && (!$resync_enc_pass)) {
                    $max_steps = 2 * $step_window;
                } else {
                    $max_steps = 2 * $step_sync_window;
                }
                $check_step = 1;

                do {
                    $additional_step = (1 - (2 * ($check_step % 2))) * intval($check_step/2);
                    $pure_calculated_token = $this->ComputeMotp($seed.$pin, $now_steps+$additional_step+$delta_step, $digits);
                    $calculated_token = $pure_calculated_token;

                    if (($need_prefix) && ($input_to_check != '') && ($this->IsUserRequestLdapPasswordEnabled())) {
                        $code_confirmed_without_pin = $calculated_token;
                        $code_confirmed = $calculated_token;
                        $input_to_check = substr($input_to_check, -strlen($code_confirmed));                            
                        $this->SetLastClearOtpValue($code_confirmed);
                    } else {
                        if ($need_prefix) {
                            $calculated_token = $pin.$calculated_token;
                        }

                        $code_confirmed_without_pin = $pure_calculated_token;
                        $code_confirmed = $calculated_token;
                        $this->SetLastClearOtpValue($code_confirmed);
                        if ('' != $this->GetChapPassword()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateChapPassword($code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateChapPassword($code_confirmed));
                        } elseif ('' != $this->GetMsChapResponse()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateMsChapResponse($code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateMsChapResponse($code_confirmed));
                        } elseif ('' != $this->GetMsChap2Response()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateMsChap2Response($real_user, $code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateMsChap2Response($real_user, $code_confirmed));
                        }
                    }

                    if (('' == $input_sync) && (!$resync_enc_pass)) {
                        // With mOTP, the code should not be prefixed, so we accept of course always input without prefix!
                        if (($input_to_check == $code_confirmed) || ($input_to_check == $code_confirmed_without_pin)) {
                            if ($input_to_check == $code_confirmed_without_pin) {
                                $code_confirmed = $code_confirmed_without_pin;
                            }
                            if (($now_steps+$additional_step+$delta_step) > $last_login_step) {
                                $this->SetUserTokenLastLogin(($now_steps+$additional_step+$delta_step) * $interval);
                                $this->SetUserTokenDeltaTime(($additional_step+$delta_step) * $interval);
                                $this->SetUserErrorCounter(0);
                                $result = 0; // OK: This is the correct token
                                $this->WriteLog("Ok: User ".$this->GetUser()." successfully logged in", FALSE, FALSE, $result, 'User');
                            } else {
                                $this->SetUserErrorCounter($error_counter+1);
                                $this->SetUserTokenLastError($now_epoch);
                                $result = 26; // ERROR: this token has already been used
                                $this->WriteLog("Error: token of user ".$this->GetUser()." already used", FALSE, FALSE, $result, 'User');
                            }
                        } else {
                            $check_step++;
                        }
                    } elseif (($input_to_check == $code_confirmed) || ($input_to_check == $code_confirmed_without_pin)) {
                        $pure_sync_calculated_token = $this->ComputeMotp($seed.$pin, $now_steps+$additional_step+$delta_step+1, $digits);
                        $sync_calculated_token = $pure_sync_calculated_token;

                        if (($need_prefix) && ($input_sync != '') && ($this->IsUserRequestLdapPasswordEnabled())) {
                            $input_sync = substr($input_sync, -strlen($code_confirmed));                            
                        } elseif ($need_prefix) {
                            $sync_calculated_token = $pin.$sync_calculated_token;
                        }
                        if ((($input_sync == $sync_calculated_token) || ($input_sync == $pure_sync_calculated_token)) && (($now_steps+$additional_step+$delta_step+1) > $last_login_step)) {
                            $this->SetUserTokenLastLogin(($now_steps+$additional_step+$delta_step+1) * $interval);
                            $this->SetUserTokenDeltaTime(($additional_step+$delta_step+1) * $interval);
                            $this->SetUserErrorCounter(0);
                            $this->SetUserLocked(0);
                            $result = 14; // INFO: token is now synchronized
                            $this->WriteLog("Info: token for user ".$this->GetUser()." is now resynchronized with a delta of ".(($additional_step+$delta_step+1) * $interval). " seconds", FALSE, FALSE, $result, 'User');
                            $result = 0; // INFO: authentication is successful, regardless of the PIN code if needed, as the PIN code is already used to generate the token
                        } else {
                            $result = 27; // ERROR: resync failed
                            $this->WriteLog("Error: resync for user ".$this->GetUser()." has failed", FALSE, FALSE, $result, 'User');
                        }
                    } else {
                        $check_step++;
                        if ($display_status) {
                            MultiotpShowStatus($check_step, $max_steps);
                        }
                    }
                } while (($check_step < $max_steps) && (90 <= $result));
                if ($display_status) {
                    echo "\r\n";
                }
                if (90 <= $result) {
                    $this->SetUserErrorCounter($error_counter+1);
                    $this->SetUserTokenLastError($now_epoch);
                    $this->WriteLog("Error: authentication failed for user ".$this->GetUser(), FALSE, FALSE, $result, 'User');
                }
                break;
            case 'hotp';
                if (('' == $input_sync)&& (!$resync_enc_pass)) {
                    $max_steps = 2 * $event_window;
                } else {
                    $max_steps = 2 * $event_sync_window;
                }
                $check_step = 1;
                do {
                    $additional_step = (1 - (2 * ($check_step % 2))) * intval($check_step/2);
                    $pure_calculated_token = $this->GenerateOathHotp($seed_bin,$last_event+$additional_step,$digits,$token_algo_suite);
                    $calculated_token = $pure_calculated_token;
                    if (($need_prefix) && ($input_to_check != '') && ($this->IsUserRequestLdapPasswordEnabled())) {
                        $code_confirmed_without_pin = $calculated_token;
                        $code_confirmed = $calculated_token;
                        $input_to_check = substr($input_to_check, -strlen($code_confirmed));                            
                        $this->SetLastClearOtpValue($code_confirmed);
                    } else {
                        if ($need_prefix) {
                            $calculated_token = $pin.$calculated_token;
                        }

                        $code_confirmed_without_pin = $pure_calculated_token;
                        $code_confirmed = $calculated_token;
                        $this->SetLastClearOtpValue($code_confirmed);
                        if ('' != $this->GetChapPassword()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateChapPassword($code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateChapPassword($code_confirmed));
                        } elseif ('' != $this->GetMsChapResponse()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateMsChapResponse($code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateMsChapResponse($code_confirmed));
                        } elseif ('' != $this->GetMsChap2Response()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateMsChap2Response($real_user, $code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateMsChap2Response($real_user, $code_confirmed));
                        }
                    }

                    if (('' == $input_sync) && (!$resync_enc_pass)) {
                        if ($input_to_check == $code_confirmed) {
                            if ($additional_step >= 1) {
                                $this->SetUserTokenLastLogin($now_epoch);
                                $this->SetUserTokenLastEvent($last_event+$additional_step);
                                $this->SetUserErrorCounter(0);
                                $result = 0; // OK: This is the correct token
                                $this->WriteLog("OK: User ".$this->GetUser()." successfully logged in", FALSE, FALSE, $result, 'User');
                            } else {
                                $this->SetUserErrorCounter($error_counter+1);
                                $this->SetUserTokenLastError($now_epoch);
                                $result = 26; // ERROR: this token has already been used
                                $this->WriteLog("Error: token of user ".$this->GetUser()." already used", FALSE, FALSE, $result, 'User');
                            }
                        } else {
                            $check_step++;
                        }
                    } elseif (($input_to_check == $code_confirmed) || ($input_to_check == $code_confirmed_without_pin)) {
                        $pure_sync_calculated_token = $this->GenerateOathHotp($seed_bin, $last_event+$additional_step+1,$digits,$token_algo_suite);
                        $sync_calculated_token = $pure_sync_calculated_token;

                        if (($need_prefix) && ($input_sync != '') && ($this->IsUserRequestLdapPasswordEnabled())) {
                            $input_sync = substr($input_sync, -strlen($code_confirmed));                            
                        } elseif ($need_prefix) {
                            $sync_calculated_token = $pin.$sync_calculated_token;
                        }
                        if ((($input_sync == $sync_calculated_token) || ($input_sync == $pure_sync_calculated_token)) && ($additional_step >= 1)) {
                            $this->SetUserTokenLastLogin($now_epoch);
                            $this->SetUserTokenLastEvent($last_event+$additional_step+1);
                            $this->SetUserErrorCounter(0);
                            $this->SetUserLocked(0);
                            $result = 14; // INFO: token is now synchronized
                            $this->WriteLog("Info: token for user ".$this->GetUser()." is now resynchronized with the last event ".($last_event+$additional_step+1), FALSE, FALSE, $result, 'User');
                            if ($input_to_check == $code_confirmed) {
                                $result = 0; // INFO: authentication is successful, as the prefix has also been typed (if any)
                            }
                        } else {
                            $result = 27; // ERROR: resync failed
                            $this->WriteLog("Error: resync for user ".$this->GetUser()." has failed", FALSE, FALSE, $result, 'User');
                        }
                    } else {
                        $check_step++;
                        if ($display_status) {
                            MultiotpShowStatus($check_step, $max_steps);
                        }
                    }
                } while (($check_step < $max_steps) && ((90 <= $result)));
                if ($display_status) {
                    echo "\r\n";
                }
                if (90 <= $result) {
                    $this->SetUserErrorCounter($error_counter+1);
                    $this->SetUserTokenLastError($now_epoch);
                    $this->WriteLog("Error: authentication failed for user ".$this->GetUser(), FALSE, FALSE, $result, 'User');
                }
                break;
            case 'yubicootp';
                $yubikey_class = new MultiotpYubikey();
                $bad_precheck = FALSE;
                if (($need_prefix) && ($input_to_check != '') && ($this->IsUserRequestLdapPasswordEnabled())) {
                    if (!$ldap_check_passed) {
                        $input_to_check.= '_BAD_LDAP_CHECK';
                        $bad_precheck = TRUE;
                    }
                    $this->SetLastClearOtpValue($input_to_check);
                } else {
                    if ($need_prefix) {
                        if ($pin != substr($input_to_check, 0, strlen($pin))) {
                            $this->SetLastClearOtpValue($input_to_check);
                            $input_to_check.= '_BAD_PREFIX';
                            $bad_precheck = TRUE;
                        }
                    }
                }

                if (!$bad_precheck) {
                    // Check only the last 32 digits, the first 12 are the serial number
                    $result = $yubikey_class->CheckYubicoOtp(substr($input_to_check, -32),
                    $seed,
                    $last_event);
                }

                if (0 == $result) {
                    $calculated_token = $input_to_check;
                    $this->SetUserTokenLastLogin($now_epoch);
                    $this->SetUserTokenLastEvent($yubikey_class->GetYubicoOtpLastCount());
                    $this->SetUserErrorCounter(0);
                    $result = 0; // OK: This is the correct token
                    $this->WriteLog("OK: User ".$this->GetUser()." successfully logged in", FALSE, FALSE, $result, 'User');
                } elseif (26 == $result) {
                    $this->SetUserErrorCounter(1); // TODO $error_counter+1, includes resync
                    $this->SetUserTokenLastError($now_epoch);
                    $result = 26; // ERROR: this token has already been used
                    $this->WriteLog("Error: token of user ".$this->GetUser()." already used", FALSE, FALSE, $result, 'User');
                } else {
                    $this->SetUserErrorCounter($error_counter+1);
                    $this->SetUserTokenLastError($now_epoch);
                    $this->WriteLog("Error: authentication failed for user ".$this->GetUser(), FALSE, FALSE, $result, 'User');
                }
                break;
            case 'totp';
                if (('' == $input_sync) && (!$resync_enc_pass)) {
                    $max_steps = 2 * $step_window;
                } else {
                    $max_steps = 2 * $step_sync_window;
                }
                $check_step = 1;
                
                $a = array();
                do {
                    $additional_step = (1 - (2 * ($check_step % 2))) * intval($check_step/2);
                    $pure_calculated_token = $this->GenerateOathHotp($seed_bin,$now_steps+$additional_step+$delta_step,$digits,$token_algo_suite);
                    $calculated_token = $pure_calculated_token;
                    
                    if (($need_prefix) && ($input_to_check != '') && ($this->IsUserRequestLdapPasswordEnabled())) {
                        $code_confirmed_without_pin =  $calculated_token;
                        $code_confirmed = $calculated_token;
                        $input_to_check = substr($input_to_check, -strlen($code_confirmed));     
                        $this->SetLastClearOtpValue($code_confirmed);
                    } else {
                        if ($need_prefix) {
                            $calculated_token = $pin.$calculated_token;
                        }

                        $code_confirmed_without_pin = $pure_calculated_token;
                        $code_confirmed = $calculated_token;
                        $this->SetLastClearOtpValue($code_confirmed);
                        if ('' != $this->GetChapPassword()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateChapPassword($code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateChapPassword($code_confirmed));
                        } elseif ('' != $this->GetMsChapResponse()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateMsChapResponse($code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateMsChapResponse($code_confirmed));
                        } elseif ('' != $this->GetMsChap2Response()) {
                            $code_confirmed_without_pin = strtolower($this->CalculateMsChap2Response($real_user, $code_confirmed_without_pin));
                            $code_confirmed = strtolower($this->CalculateMsChap2Response($real_user, $code_confirmed));
                        }
                    }
                    
                    if (('' == $input_sync) && (!$resync_enc_pass)) {
                        if ($input_to_check == $code_confirmed) {
                            if (($now_steps+$additional_step+$delta_step) > $last_login_step) {
                                $this->SetUserTokenLastLogin(($now_steps+$additional_step+$delta_step) * $interval);
                                $this->SetUserTokenDeltaTime(($additional_step+$delta_step) * $interval);
                                $this->SetUserErrorCounter(0);
                                $result = 0; // OK: This is the correct token
                                $this->WriteLog("OK: User ".$this->GetUser()." successfully logged in", FALSE, FALSE, $result, 'User');
                            } else {
                                $this->SetUserErrorCounter($error_counter+1);
                                $this->SetUserTokenLastError($now_epoch);
                                $result = 26; // ERROR: this token has already been used
                                $this->WriteLog("Error: token of user ".$this->GetUser()." already used", FALSE, FALSE, $result, 'User');
                            }
                        } else {
                            $check_step++;
                        }
                    } elseif (($input_to_check == $code_confirmed) || ($input_to_check == $code_confirmed_without_pin)) {
                        $pure_sync_calculated_token = $this->GenerateOathHotp($seed_bin,$now_steps+$additional_step+$delta_step+1,$digits,$token_algo_suite);
                        $sync_calculated_token = $pure_sync_calculated_token;

                        if (($need_prefix) && ($input_sync != '') && ($this->IsUserRequestLdapPasswordEnabled())) {
                            $input_sync = substr($input_sync, -strlen($code_confirmed));                            
                        } elseif ($need_prefix) {
                            $sync_calculated_token = $pin.$sync_calculated_token;
                        }
                        if ((($input_sync == $sync_calculated_token) || ($input_sync == $pure_sync_calculated_token)) && (($now_steps+$additional_step+$delta_step) > $last_login_step)) {
                            $this->SetUserTokenLastLogin(($now_steps+$additional_step+$delta_step+1) * $interval);
                            $this->SetUserTokenDeltaTime(($additional_step+$delta_step+1) * $interval);
                            $this->SetUserErrorCounter(0);
                            $this->SetUserLocked(0);
                            $result = 14; // INFO: token is now synchronized
                            $this->WriteLog("Info: token for user ".$this->GetUser()." is now resynchronized with a delta of ".(($additional_step+$delta_step+1) * $interval). " seconds", FALSE, FALSE, $result, 'User');
                            if ($input_to_check == $code_confirmed) {
                                $result = 0; // INFO: authentication is successful, as the prefix has also been typed (if any)
                            }
                        } else {
                            $result = 27; // ERROR: resync failed
                            $this->WriteLog("Error: resync for user ".$this->GetUser()." has failed", FALSE, FALSE, $result, 'User');
                        }
                    } else {
                        $check_step++;
                        if ($display_status) {
                            MultiotpShowStatus($check_step, $max_steps);
                        }
                    }
                } while (($check_step < $max_steps) && (90 <= $result));

                if ($display_status) {
                    echo "\r\n";
                }
                if (90 <= $result) {
                    $this->SetUserErrorCounter($error_counter+1);
                    $this->SetUserTokenLastError($now_epoch);
                    $this->WriteLog("Error: authentication failed for user ".$this->GetUser(), FALSE, FALSE, $result, 'User');
                }
                break;
            default:
                $result = 23;
                $this->WriteLog("Error: ".$this->GetUserAlgorithm()." algorithm is unknown", FALSE, FALSE, $result, 'User');
        }

        if (90 <= $result) {
            if ($this->GetVerboseFlag()) {
                if ('' != $this->GetChapPassword()) {
                    $this->WriteLog("*(authentication typed by the user is CHAP encrypted)", FALSE, FALSE, $result, 'User');
                } elseif ('' != $this->GetMsChapResponse()) {
                    $this->WriteLog("*(authentication typed by the user is MS-CHAP encrypted)", FALSE, FALSE, $result, 'User');
                } elseif ('' != $this->GetMsChap2Response()) {
                    $this->WriteLog("*(authentication typed by the user is MS-CHAP V2 encrypted)", FALSE, FALSE, $result, 'User');
                } elseif ((strlen($input_to_check) == strlen($calculated_token))) {
                    $this->WriteLog("*(authentication typed by the user: ".$input_to_check.")", FALSE, FALSE, $result, 'User');
                } else {
                    $result = 98;
                    $this->WriteLog("*(authentication typed by the user is ".strlen($input_to_check)." chars long instead of ".strlen($calculated_token)." chars)", FALSE, FALSE, $result, 'User');
                }
            } elseif (('' == $this->GetChapPassword()) &&
                      ('' == $this->GetMsChapResponse()) &&
                      ('' == $this->GetMsChap2Response()) &&
                      ((strlen($input_to_check) != strlen($calculated_token)))
                     ) {
                $result = 98;
                $this->WriteLog("Error: authentication typed by the user is ".strlen($input_to_check)." chars long instead of ".strlen($calculated_token)." chars", FALSE, FALSE, $result, 'User');
            }
        }

        if ($this->GetUserErrorCounter() >= $this->GetMaxBlockFailures()) {
            $this->SetUserLocked(1);
        }

        if (0 == $result) {
            $this->AddExtraRadiusInfo();
        }
        return $result;
    }
    
    /**
     * Return the user algorithm to use for the process
     *  - TOTP for now :)
     * 
     * @return string
     */
    function GetUserAlgorithm($user = '') {
        return 'totp';
    }
}

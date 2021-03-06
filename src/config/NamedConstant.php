<?php
//UserCredential constants for user authentication
if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_LOGGEDOUT'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_LOGGEDOUT', 1);
}

if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN', 2);
}

if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_LOCKED1'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_LOCKED1', 3);
}

if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_LOCKED2'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_LOCKED2', 4);
}

if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_RESET'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_RESET', 5);
}

if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_SUSPENDED'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_SUSPENDED', 6);
}

if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_AUTHFAILED'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_AUTHFAILED', 7);
}

if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_WEAKPASSWD'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_WEAKPASSWD', 8);
}

if (!(defined('USERCREDENTIAL_ACCOUNTSTATE_MULTIFACTSTEP1'))) {
    define('USERCREDENTIAL_ACCOUNTSTATE_MULTIFACTSTEP1', 9);
}

//UserCredential constants for account policy actions
if (!(defined('USERCREDENTIAL_ACCOUNTPOLICY_VALID'))) {
    define('USERCREDENTIAL_ACCOUNTPOLICY_VALID', 1);
}

if (!(defined('USERCREDENTIAL_ACCOUNTPOLICY_EXPIRED'))) {
    define('USERCREDENTIAL_ACCOUNTPOLICY_EXPIRED', 2);
}

if (!(defined('USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT1'))) {
    define('USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT1', 3);
}

if (!(defined('USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT2'))) {
    define('USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT2', 4);
}

if (!(defined('USERCREDENTIAL_ACCOUNTPOLICY_REPEATERROR'))) {
    define('USERCREDENTIAL_ACCOUNTPOLICY_REPEATERROR', 5);
}

if (!(defined('USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD'))) {
    define('USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD', 6);
}

if (!(defined('USERCREDENTIAL_ACCOUNTPOLICY_NAMEINPASSWD'))) {
    define('USERCREDENTIAL_ACCOUNTPOLICY_NAMEINPASSWD', 7);
}

//Password strength constants for use with phpclass package
if (!(defined('PHPASS_PASSWORDSTRENGTHADAPTER_NIST'))) {
    define('PHPASS_PASSWORDSTRENGTHADAPTER_NIST', 0);
}

if (!(defined('PHPASS_PASSWORDSTRENGTHADAPTER_WOLFRAM'))) {
    define('PHPASS_PASSWORDSTRENGTHADAPTER_WOLFRAM', 1);
}

//Password login platform types
if (!(defined('USERCREDENTIAL_PASSWORDLOGINPLATFORM_NATIVE'))) {
    define('USERCREDENTIAL_PASSWORDLOGINPLATFORM_NATIVE', 1);
}

if (!(defined('USERCREDENTIAL_PASSWORDLOGINPLATFORM_LDAP'))) {
    define('USERCREDENTIAL_PASSWORDLOGINPLATFORM_LDAP', 2);
}

<?php
//UserCredential constants for user authentication
const USERCREDENTIAL_ACCOUNTSTATE_LOGGEDOUT   = 1;
const USERCREDENTIAL_ACCOUNTSTATE_LOGGEDIN    = 2;
const USERCREDENTIAL_ACCOUNTSTATE_LOCKED1     = 3;
const USERCREDENTIAL_ACCOUNTSTATE_LOCKED2     = 4;
const USERCREDENTIAL_ACCOUNTSTATE_RESET       = 5;
const USERCREDENTIAL_ACCOUNTSTATE_SUSPENDED   = 6;
const USERCREDENTIAL_ACCOUNTSTATE_AUTHFAILED  = 7;
const USERCREDENTIAL_ACCOUNTSTATE_WEAKPASSWD  = 8;

//UserCredential constants for account policy actions
const USERCREDENTIAL_ACCOUNTPOLICY_VALID         = 1;
const USERCREDENTIAL_ACCOUNTPOLICY_EXPIRED       = 2;
const USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT1 = 3;
const USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT2 = 4;
const USERCREDENTIAL_ACCOUNTPOLICY_REPEATERROR   = 5;
const USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD    = 6;
const USERCREDENTIAL_ACCOUNTPOLICY_NAMEINPASSWD  = 7;

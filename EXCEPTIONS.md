# USERCREDENTIAL EXCEPTION CODES

### EXCEPTIONS FOR USERCREDENTIAL MANAGER

|CODE   |   MESSAGE|
|---|---|
| 1000 | The user profile is not properly initialized  |
| 1001 | The entropy object should be an array or implement ArrayAccess interface  |
| 1002 | The minimum password length hasn\'t been set  |
| 1003 | The maximum allowed consecutive character repetition hasn\'t been set  |
| 1004 | The uppercase settings must be an array containing toggle and min upper length |
| 1005 | The lowercase settings must be an array containing toggle and min lower length  |
| 1006 | The numeric settings must be an array containing toggle and min lower length  |
| 1007 | The special character settings must be an array containing toggle and min length  |
| 1009 | The illegal attempts limit hasn\'t been set  |
| 1010 | The password reset frequency hasn\'t been set  |
| 1011 | The password repeat minimum has not been set |
| 1012 | The illegal attempts penalty seconds has not been set  |
| 1013 | The regex pattern is not set|
| 1015 | A fatal error occured in the password validation  |
| 1016 | The username and password are not set  |
| 1022 | Phpass strength adapter calculator must be NIST or Wolfram. Wrong Flag provivded  |
| 1023 | Multi factor auth is flagged on, but the encryption key length is not properly initialized  |
| 1024 | TOTP info is not set in the users profile  |
| 1025 | The encryption key string length for TOTP hashing is too short  |
| 1026 | The maximum allowed consecutive character repetition for characters of the same class hasn\'t been set
| 1027 | Tenancy problem with your account. Please contact your Administrator

### EXCEPTIONS FOR USERCREDENTIAL BASIC PASSWORD LOGIN SERVICE

|CODE   |   MESSAGE|
|---|---|
| 2000 | The usercredential login service is not initialized with all parameters  |

### EXCEPTIONS FOR USERCREDENTIAL TWO FACTOR LOGIN SERVICES

|CODE   |   MESSAGE|
|---|---|
| 2100 | The multi factor stages register is initialized with an an unknown state  |
| 2101 | The current stage of the multi factor auth process is in an unknown state  |
| 2102 | The user TOTP profile is not initialized properly  |
| 2104 | The TOTP Profile must be an array  |
| 2105 | The encryption key length must be an integer  |
| 2106 | Cannot validate a TOTP token when username is not set  |
| 2107 | The TOTP token for the current user does not exist  |

### EXCEPTIONS FOR THE USER AUTHENTICATION PROCESS

Note that for some of these messages, the Exception Message MAY not be as described in the table below because they are built in runtime using the User account policy in force at the time.

|CODE   |   MESSAGE|
|---|---|
| \USERCREDENTIAL_ACCOUNTPOLICY_VALID | Login failed. Wrong username or password  |
| \USERCREDENTIAL_ACCOUNTPOLICY_EXPIRED | The password has expired and must be changed  |
| \USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT1 | Account has failed multiple logins and has been temporarily locked for a few minutes  |
| \USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT2 | Account has failed excessive logins and has been permanently locked  |
| \USERCREDENTIAL_ACCOUNTPOLICY_ATTEMPTLIMIT2 | Account has failed excessive logins and has been permanently locked  |
| \USERCREDENTIAL_ACCOUNTPOLICY_REPEATERROR | User cannot repeat recently used passwords  |
| \USERCREDENTIAL_ACCOUNTPOLICY_WEAKPASSWD | The password does not meet the minimum entropy  |
| \USERCREDENTIAL_ACCOUNTPOLICY_NAMEINPASSWD | Password cannot contain username or any of your names (or reverse of either)  |

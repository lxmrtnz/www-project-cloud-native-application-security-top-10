CNAS-3: Improper authentication & authorization
===========================================

## Overview

Improper authentication and authorization are both vulnerabilities with high likelihoods of exploitation. 

## Description

Improper authentication occues when a user claims to have a given identity and a product fails to prove that the claim is correct. 
Improper Authroization occurs when a product fails to perform a correct authroization check when a user atempts to access resources or perform an action.

## How To Prevent

Deny by Default
Enforce Least Privileges
Appropriate Logging

## Example Attack Scenarios

### Scenario #1

CVE-2022-1466
Improper authorization allowed Redhat users to be added to the master realm when using Single Sign-On when no repsective permission was granted.

### Scenario #2

CVE-2022-30670
RoboHelp was affected by improper authorization. Attackers could leverage this to gain full admin privileges. This was possible by manipulating API 
requests to elevate account privileges.

## References

https://cwe.mitre.org/data/definitions/287.html
https://cwe.mitre.org/data/definitions/285.html
https://owasp.org/www-community/Broken_Access_Control
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
https://www.cvedetails.com/cve/CVE-2022-1466
https://www.cvedetails.com/cwe-details/285/Improper-Access-Control-Authorization-.html
https://helpx.adobe.com/security/products/robohelp-server/apsb22-31.html

### External

https://cwe.mitre.org/data/definitions/287.html
https://cwe.mitre.org/data/definitions/285.html
https://owasp.org/www-community/Broken_Access_Control
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
https://www.cvedetails.com/cve/CVE-2022-1466
https://www.cvedetails.com/cwe-details/285/Improper-Access-Control-Authorization-.html
https://helpx.adobe.com/security/products/robohelp-server/apsb22-31.html
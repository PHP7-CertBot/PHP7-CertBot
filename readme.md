# PHP7-CertBot
[![Build Status](https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/badges/build.png?b=master)](https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/build-status/master)
[![StyleCI](https://github.styleci.io/repos/62511938/shield?branch=master)](https://github.styleci.io/repos/62511938?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/?branch=master)

This is a RESTful/JSON api for ENTERPRISE certificate management. Why enterprise? A few reasons:
* Centralized monitoring, management, tracking, issuing, renewal, and authorization of both internal and external certificates
* Multiple accounts for both public ACME certificates, each account can use a different ACME CA and different authorization method
* Multiple accounts for enterprise root/issuing/enrollment CAs
* ACME accounts support DNS-01 with automated integration into Neustar/Ultradns and CloudFlare DNS APIs
* Delegated roles and responsibilities around enterprise certificate management, limitations in zones different accounts can issue certs for
* User / group management has been upgraded to Oauth2/OpenID via Azure AD.

# Application Stack
CertBot is an app running on Laravel 5.5 + PHP7-Laravel5-EnterpriseAuth that is both an Acme client for Let's Encrypt as well as certificate authority manager
The current deployment is: Ubuntu 18.04 + Nginx + PHP 7.2 + Mysql 5.7

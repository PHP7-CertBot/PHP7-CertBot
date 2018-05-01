# PHP7-CertBot
[![Build Status](https://scrutinizer-ci.com/g/metaclassing/PHP7-CertBot/badges/build.png?b=master)](https://scrutinizer-ci.com/g/metaclassing/PHP7-CertBot/build-status/master)
[![Style-CI](https://styleci.io/repos/62511938/shield?branch=master)]()
[![Code Coverage](https://scrutinizer-ci.com/g/metaclassing/PHP7-CertBot/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/metaclassing/PHP7-CertBot/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/metaclassing/PHP7-CertBot/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/metaclassing/PHP7-CertBot/?branch=master)

This is a RESTful/JSON api for ENTERPRISE certificate management. Why enterprise? A few reasons:
* Centralized management, tracking, issuing, renewal, and authorization of both internal and external certificates
* Multiple accounts for both public ACME certificates, each account can use a different ACME CA and different authorization method
* Multiple accounts for enterprise root/issuing/enrollment CAs
* ACME accounts support both HTTP-01 and DNS-01 with automated integration into Verisign managed DNS as well as CloudFlare DNS APIs
* Delegated roles and responsibilities around enterprise certificate management, limitations in zones different accounts can issue certs for
* User management CAN function without LDAP, but the user controller and group membership for roles is automated in this package use it

# Application Stack
CertBot is an app running on Laravel 5.2 + Dingo + JWT + Bouncer that is both an Acme client for Let's Encrypt as well as certificate authority manager
The current deployment is: Ubuntu 16.04 + Nginx + PHP 7 + Mysql 5.7
Authentication is possible via client TLS certificate, or LDAP if enabled and configured. User management is not in scope for certbot
Bouncer roles manage rights to the accounts and account certificates via the application http controllers

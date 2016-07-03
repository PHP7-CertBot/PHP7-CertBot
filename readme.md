# php7-certbot

CertBot is an app running on Laravel 5.2 + Dingo + JWT + Bouncer that is both an Acme client for Let's Encrypt as well as certificate authority manager.

This is an API application - there is no certbot client code in this repository. It can be called via anything capable of interacting with a RESTful/JSON API.

Authentication is possible via client TLS certificate, or LDAP if enabled and configured. User management is not in scope for certbot.

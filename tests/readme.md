# php artisan migrate:refresh --seed ; ./vendor/bin/phpunit

Rolled back: 2016_06_24_171910_create_ca_tables
Rolled back: 2016_06_18_134139_create_acme_tables
Rolled back: 2015_05_24_155446_create_bouncer_tables
Rolled back: 2014_10_12_000000_create_users_table
Migrated: 2014_10_12_000000_create_users_table
Migrated: 2015_05_24_155446_create_bouncer_tables
Migrated: 2016_06_18_134139_create_acme_tables
Migrated: 2016_06_24_171910_create_ca_tables
Seeded: UsersTableSeeder
Seeded: AcmeAccountTableSeeder
Seeded: CaAccountTableSeeder
Seeded: BouncerTableSeeder
PHPUnit 4.8.26 by Sebastian Bergmann and contributors.

.
AcmeAccountTest::testAcmeAccountAPI Starting Acme Account API tests
AcmeAccountTest::seedUserAccounts Creating test user accounts
AcmeAccountTest::getJWT Generating JWT for role Admin
AcmeAccountTest::seedAcmeAccounts Creating test Acme account
AcmeAccountTest::seedBouncerUserRoles Seeding user roles with different access levels
AcmeAccountTest::getJWT Generating JWT for role Manager
AcmeAccountTest::getAccounts Loading latest accounts visible to current role - found 1 accounts
AcmeAccountTest::getAccountCertificates Loading certificates for accounts - found 0 in account 1
AcmeAccountTest::testAcmeAccountAPI Creating and signing new certificate with Acme authority
AcmeAccountTest::createCertificate Creating new certificate for test zone
AcmeAccountTest::getAccountCertificates Loading certificates for accounts - found 1 in account 1
AcmeAccountTest::generateCSR Generating csr for example cert
AcmeAccountTest::signCSR Signing csr for example cert
AcmeAccountTest::validateSignatures Validating Acme signed certificate signatures with openssl
AcmeAccountTest::validateSignatures Validating CA and Cert signatures with OpenSSL cert: OK
AcmeAccountTest::validateUserPermissions Validating user roles have proper access
AcmeAccountTest::getJWT Generating JWT for role Manager
AcmeAccountTest::validateAccountRouteAccess Validating account route access conditions
AcmeAccountTest::validateAccountRouteAccess User can list accounts: 1
AcmeAccountTest::validateAccountRouteAccess User can view assigned account: 1
AcmeAccountTest::validateAccountRouteAccess User can create new account: 0
AcmeAccountTest::validateAccountRouteAccess User can edit assigned account: 1
AcmeAccountTest::validateAccountRouteAccess User can delete assigned account: 0
AcmeAccountTest::validateCertificateRouteAccess Validating certificate route access conditions
AcmeAccountTest::validateCertificateRouteAccess User can certificates: 1
AcmeAccountTest::validateCertificateRouteAccess User can view assigned certificate: 1
AcmeAccountTest::validateCertificateRouteAccess User can create new certificate: 1
AcmeAccountTest::validateCertificateRouteAccess User can generate csr: 1
AcmeAccountTest::validateCertificateRouteAccess SKIPPING USER SIGN TEST due to ACME validation frequency: 1
AcmeAccountTest::validateCertificateRouteAccess User can renew cert: 1
AcmeAccountTest::validateCertificateRouteAccess User can view pkcs12: 1
AcmeAccountTest::validateCertificateRouteAccess User can view pem: 1
AcmeAccountTest::getJWT Generating JWT for role Signer
AcmeAccountTest::validateAccountRouteAccess Validating account route access conditions
AcmeAccountTest::validateAccountRouteAccess User can list accounts: 1
AcmeAccountTest::validateAccountRouteAccess User can view assigned account: 1
AcmeAccountTest::validateAccountRouteAccess User can create new account: 0
AcmeAccountTest::validateAccountRouteAccess User can edit assigned account: 0
AcmeAccountTest::validateAccountRouteAccess User can delete assigned account: 0
AcmeAccountTest::validateCertificateRouteAccess Validating certificate route access conditions
AcmeAccountTest::validateCertificateRouteAccess User can certificates: 1
AcmeAccountTest::validateCertificateRouteAccess User can view assigned certificate: 1
AcmeAccountTest::validateCertificateRouteAccess User can create new certificate: 1
AcmeAccountTest::validateCertificateRouteAccess User can generate csr: 1
AcmeAccountTest::validateCertificateRouteAccess SKIPPING USER SIGN TEST due to ACME validation frequency: 1
AcmeAccountTest::validateCertificateRouteAccess User can renew cert: 1
AcmeAccountTest::validateCertificateRouteAccess User can view pkcs12: 1
AcmeAccountTest::validateCertificateRouteAccess User can view pem: 1
AcmeAccountTest::getJWT Generating JWT for role Operator
AcmeAccountTest::validateAccountRouteAccess Validating account route access conditions
AcmeAccountTest::validateAccountRouteAccess User can list accounts: 1
AcmeAccountTest::validateAccountRouteAccess User can view assigned account: 1
AcmeAccountTest::validateAccountRouteAccess User can create new account: 0
AcmeAccountTest::validateAccountRouteAccess User can edit assigned account: 0
AcmeAccountTest::validateAccountRouteAccess User can delete assigned account: 0
AcmeAccountTest::validateCertificateRouteAccess Validating certificate route access conditions
AcmeAccountTest::validateCertificateRouteAccess User can certificates: 1
AcmeAccountTest::validateCertificateRouteAccess User can view assigned certificate: 1
AcmeAccountTest::validateCertificateRouteAccess User can create new certificate: 1
AcmeAccountTest::validateCertificateRouteAccess User can generate csr: 1
AcmeAccountTest::validateCertificateRouteAccess SKIPPING USER SIGN TEST due to ACME validation frequency: 0
AcmeAccountTest::validateCertificateRouteAccess User can renew cert: 0
AcmeAccountTest::validateCertificateRouteAccess User can view pkcs12: 1
AcmeAccountTest::validateCertificateRouteAccess User can view pem: 1
AcmeAccountTest::getJWT Generating JWT for role Unauthorized
AcmeAccountTest::validateAccountRouteAccess Validating account route access conditions
AcmeAccountTest::validateAccountRouteAccess User can list accounts: 0
AcmeAccountTest::validateAccountRouteAccess User can view assigned account: 0
AcmeAccountTest::validateAccountRouteAccess User can create new account: 0
AcmeAccountTest::validateAccountRouteAccess User can edit assigned account: 0
AcmeAccountTest::validateAccountRouteAccess User can delete assigned account: 0
AcmeAccountTest::validateCertificateRouteAccess Validating certificate route access conditions
AcmeAccountTest::validateCertificateRouteAccess User can certificates: 0
AcmeAccountTest::validateCertificateRouteAccess User can view assigned certificate: 0
AcmeAccountTest::validateCertificateRouteAccess User can create new certificate: 0
AcmeAccountTest::validateCertificateRouteAccess User can generate csr: 0
AcmeAccountTest::validateCertificateRouteAccess SKIPPING USER SIGN TEST due to ACME validation frequency: 0
AcmeAccountTest::validateCertificateRouteAccess User can renew cert: 0
AcmeAccountTest::validateCertificateRouteAccess User can view pkcs12: 0
AcmeAccountTest::validateCertificateRouteAccess User can view pem: 0
AcmeAccountTest::testAcmeAccountAPI All verification complete, testing successful, database has been cleaned up.
CaAccountTest::testCaAccountAPI Starting CA Account API tests
CaAccountTest::seedUserAccounts Creating test user accounts
CaAccountTest::getJWT Generating JWT for role Admin
CaAccountTest::seedCaAccounts Creating test CA account
CaAccountTest::seedCaAccounts Creating test CA certificate
CaAccountTest::seedBouncerUserRoles Seeding user roles with different access levels
CaAccountTest::getJWT Generating JWT for role Manager
CaAccountTest::getAccounts Loading latest accounts visible to current role - found 1 accounts
CaAccountTest::getAccountCertificates Loading certificates for accounts - found 1 in account 1
CaAccountTest::testCaAccountAPI Setting up our test CA
CaAccountTest::selfSignCaAccountCertificates Self signing phpUnit Root CA cert
CaAccountTest::testCaAccountAPI Creating and signing new certificate with our CA
CaAccountTest::createCertificate Creating new certificate for example.com
CaAccountTest::getAccountCertificates Loading certificates for accounts - found 2 in account 1
CaAccountTest::generateCSR Generating csr for example.com cert
CaAccountTest::signCSR Signing csr for example.com cert
CaAccountTest::validateSignatures Validating CA and certificate signatures with openssl
CaAccountTest::validateSignatures Validating CA and Cert signatures with OpenSSL
CaAccountTest::validateUserPermissions Validating user roles have proper access
CaAccountTest::getJWT Generating JWT for role Manager
CaAccountTest::validateAccountRouteAccess Validating account route access conditions
CaAccountTest::validateAccountRouteAccess User can list accounts: 1
CaAccountTest::validateAccountRouteAccess User can view assigned account: 1
CaAccountTest::validateAccountRouteAccess User can create new account: 0
CaAccountTest::validateAccountRouteAccess User can edit assigned account: 1
CaAccountTest::validateAccountRouteAccess User can delete assigned account: 0
CaAccountTest::validateCertificateRouteAccess Validating certificate route access conditions
CaAccountTest::validateCertificateRouteAccess User can certificates: 1
CaAccountTest::validateCertificateRouteAccess User can view assigned certificate: 1
CaAccountTest::validateCertificateRouteAccess User can create new certificate: 1
CaAccountTest::validateCertificateRouteAccess User can generate csr: 1
CaAccountTest::validateCertificateRouteAccess User can sign csr: 1
CaAccountTest::validateCertificateRouteAccess User can renew cert: 1
CaAccountTest::validateCertificateRouteAccess User can view pkcs12: 1
CaAccountTest::validateCertificateRouteAccess User can view pem: 1
CaAccountTest::getJWT Generating JWT for role Signer
CaAccountTest::validateAccountRouteAccess Validating account route access conditions
CaAccountTest::validateAccountRouteAccess User can list accounts: 1
CaAccountTest::validateAccountRouteAccess User can view assigned account: 1
CaAccountTest::validateAccountRouteAccess User can create new account: 0
CaAccountTest::validateAccountRouteAccess User can edit assigned account: 0
CaAccountTest::validateAccountRouteAccess User can delete assigned account: 0
CaAccountTest::validateCertificateRouteAccess Validating certificate route access conditions
CaAccountTest::validateCertificateRouteAccess User can certificates: 1
CaAccountTest::validateCertificateRouteAccess User can view assigned certificate: 1
CaAccountTest::validateCertificateRouteAccess User can create new certificate: 1
CaAccountTest::validateCertificateRouteAccess User can generate csr: 1
CaAccountTest::validateCertificateRouteAccess User can sign csr: 1
CaAccountTest::validateCertificateRouteAccess User can renew cert: 1
CaAccountTest::validateCertificateRouteAccess User can view pkcs12: 1
CaAccountTest::validateCertificateRouteAccess User can view pem: 1
CaAccountTest::getJWT Generating JWT for role Operator
CaAccountTest::validateAccountRouteAccess Validating account route access conditions
CaAccountTest::validateAccountRouteAccess User can list accounts: 1
CaAccountTest::validateAccountRouteAccess User can view assigned account: 1
CaAccountTest::validateAccountRouteAccess User can create new account: 0
CaAccountTest::validateAccountRouteAccess User can edit assigned account: 0
CaAccountTest::validateAccountRouteAccess User can delete assigned account: 0
CaAccountTest::validateCertificateRouteAccess Validating certificate route access conditions
CaAccountTest::validateCertificateRouteAccess User can certificates: 1
CaAccountTest::validateCertificateRouteAccess User can view assigned certificate: 1
CaAccountTest::validateCertificateRouteAccess User can create new certificate: 1
CaAccountTest::validateCertificateRouteAccess User can generate csr: 1
CaAccountTest::validateCertificateRouteAccess User can sign csr: 0
CaAccountTest::validateCertificateRouteAccess User can renew cert: 0
CaAccountTest::validateCertificateRouteAccess User can view pkcs12: 1
CaAccountTest::validateCertificateRouteAccess User can view pem: 1
CaAccountTest::getJWT Generating JWT for role Unauthorized
CaAccountTest::validateAccountRouteAccess Validating account route access conditions
CaAccountTest::validateAccountRouteAccess User can list accounts: 0
CaAccountTest::validateAccountRouteAccess User can view assigned account: 0
CaAccountTest::validateAccountRouteAccess User can create new account: 0
CaAccountTest::validateAccountRouteAccess User can edit assigned account: 0
CaAccountTest::validateAccountRouteAccess User can delete assigned account: 0
CaAccountTest::validateCertificateRouteAccess Validating certificate route access conditions
CaAccountTest::validateCertificateRouteAccess User can certificates: 0
CaAccountTest::validateCertificateRouteAccess User can view assigned certificate: 0
CaAccountTest::validateCertificateRouteAccess User can create new certificate: 0
CaAccountTest::validateCertificateRouteAccess User can generate csr: 0
CaAccountTest::validateCertificateRouteAccess User can sign csr: 0
CaAccountTest::validateCertificateRouteAccess User can renew cert: 0
CaAccountTest::validateCertificateRouteAccess User can view pkcs12: 0
CaAccountTest::validateCertificateRouteAccess User can view pem: 0
CaAccountTest::testCaAccountAPI All verification complete, testing successful, database has been cleaned up.

Time: 39.39 seconds, Memory: 16.00MB

OK (3 tests, 110 assertions)


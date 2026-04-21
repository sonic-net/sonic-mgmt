==============================
Community Crypto Release Notes
==============================

.. contents:: Topics

v3.0.5
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Smaller code cleanup (https://github.com/ansible-collections/community.crypto/pull/963).

v3.0.4
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Avoid deprecated functionality in ansible-core 2.20 (https://github.com/ansible-collections/community.crypto/pull/953).

v3.0.3
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_* modules - also retry on HTTP responses 502 Bad Gateway and 504 Gateway Timeout. The latter is needed for ZeroSSL, which seems to have a lot of 504s (https://github.com/ansible-collections/community.crypto/issues/945, https://github.com/ansible-collections/community.crypto/pull/947).
- acme_* modules - increase the maximum amount of retries from 10 to 20 to accomodate ZeroSSL's buggy implementation (https://github.com/ansible-collections/community.crypto/pull/949).

v3.0.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- Improve error message when loading a private key fails due to correct private key files or wrong passwords. Also include the original cryptography error since it likely contains more helpful information (https://github.com/ansible-collections/community.crypto/issues/936, https://github.com/ansible-collections/community.crypto/pull/939).

v3.0.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- openssl_csr and openssl_csr_pipe - the idempotency check for ``key_usage`` resulted in a crash if ``Key Agreement``/``keyAgreement`` was not set (https://github.com/ansible-collections/community.crypto/issues/934, https://github.com/ansible-collections/community.crypto/pull/935).

v3.0.0
======

Release Summary
---------------

New major release of community.crypto with a lot of code modernization.
This release drops compatibility for ansible-core before 2.17, for Python
before 3.7, and for cryptography before 3.3.
It also removes all Entrust modules, and the Entrust provider for the
``community.crypto.x509_certificate*`` modules.

See below for a more detailled list of changes.

Minor Changes
-------------

- No longer provide cryptography's ``backend`` parameter. This will break with cryptography < 3.1 (https://github.com/ansible-collections/community.crypto/pull/878).
- On cryptography 36.0.0+, always use ``public_bytes()`` for X.509 extension objects instead of using cryptography internals to obtain DER value of extension (https://github.com/ansible-collections/community.crypto/pull/878).
- Python code modernization: add type hints and type checking (https://github.com/ansible-collections/community.crypto/pull/885).
- Python code modernization: avoid unnecessary string conversion (https://github.com/ansible-collections/community.crypto/pull/880).
- Python code modernization: avoid using ``six`` (https://github.com/ansible-collections/community.crypto/pull/884).
- Python code modernization: remove Python 3 specific code (https://github.com/ansible-collections/community.crypto/pull/877).
- Python code modernization: update ``__future__`` imports, remove Python 2 specific boilerplates (https://github.com/ansible-collections/community.crypto/pull/876).
- Python code modernization: use ``unittest.mock`` instead of ``ansible_collections.community.internal_test_tools.tests.unit.compat.mock`` (https://github.com/ansible-collections/community.crypto/pull/881).
- Python code modernization: use f-strings instead of ``%`` and ``str.format()`` (https://github.com/ansible-collections/community.crypto/pull/875).
- Remove ``backend`` parameter from internal code whenever possible (https://github.com/ansible-collections/community.crypto/pull/883).
- Remove various compatibility code for cryptography < 3.3 (https://github.com/ansible-collections/community.crypto/pull/878).
- Remove various no longer needed abstraction layers for multiple backends (https://github.com/ansible-collections/community.crypto/pull/912).
- Remove vendored copy of ``distutils.version`` in favor of vendored copy included with ansible-core 2.12+ (https://github.com/ansible-collections/community.crypto/pull/371).
- Various code refactorings (https://github.com/ansible-collections/community.crypto/pull/905, https://github.com/ansible-collections/community.crypto/pull/909, https://github.com/ansible-collections/community.crypto/pull/911, https://github.com/ansible-collections/community.crypto/pull/913, https://github.com/ansible-collections/community.crypto/pull/914, https://github.com/ansible-collections/community.crypto/pull/917).
- acme_* modules - improve parsing of ``Retry-After`` reply headers in regular ACME requests (https://github.com/ansible-collections/community.crypto/pull/890).
- action_module plugin utils - remove compatibility with older ansible-core/ansible-base/Ansible versions (https://github.com/ansible-collections/community.crypto/pull/872).
- x509_certificate, x509_certificate_pipe - the ``ownca_version`` and ``selfsigned_version`` parameters explicitly only allow the value ``3``. The module already failed for other values in the past, now this is validated as part of the module argument spec (https://github.com/ansible-collections/community.crypto/pull/890).

Breaking Changes / Porting Guide
--------------------------------

- All doc_fragments are now private to the collection and must not be used from other collections or unrelated plugins/modules. Breaking changes in these can happen at any time, even in bugfix releases (https://github.com/ansible-collections/community.crypto/pull/898).
- All module_utils and plugin_utils are now private to the collection and must not be used from other collections or unrelated plugins/modules. Breaking changes in these can happen at any time, even in bugfix releases (https://github.com/ansible-collections/community.crypto/pull/887).
- Ignore value of ``select_crypto_backend`` for all modules except acme_* and ..., and always assume the value ``auto``. This ensures that the ``cryptography`` version is always checked (https://github.com/ansible-collections/community.crypto/pull/883).
- The validation for relative timestamps is now more strict. A string starting with ``+`` or ``-`` must be valid, otherwise validation will fail. In the past such strings were often silently ignored, and in many cases the code which triggered the validation was not able to handle no result (https://github.com/ansible-collections/community.crypto/pull/885).
- acme.certificates module utils - the ``retrieve_acme_v1_certificate()`` helper function has been removed (https://github.com/ansible-collections/community.crypto/pull/873).
- get_certificate - the default for ``asn1_base64`` changed from ``false`` to ``true`` (https://github.com/ansible-collections/community.crypto/pull/873).
- x509_crl - the ``mode`` parameter no longer denotes the update mode, but the CRL file mode. Use ``crl_mode`` instead for the update mode (https://github.com/ansible-collections/community.crypto/pull/873).

Deprecated Features
-------------------

- acme_certificate - deprecate the ``agreement`` option which has no more effect. It will be removed from community.crypto 4.0.0 (https://github.com/ansible-collections/community.crypto/pull/891).
- acme_certificate - the option ``modify_account``'s default value ``true`` has been deprecated. It will change to ``false`` in community.crypto 4.0.0. We recommend to set the option to an explicit value to avoid deprecation warnings, and to prefer setting it to ``false`` already now. Better use the ``community.crypto.acme_account`` module instead (https://github.com/ansible-collections/community.crypto/issues/924).
- openssl_pkcs12 - deprecate the ``maciter_size`` option which has no more effect. It will be removed from community.crypto 4.0.0 (https://github.com/ansible-collections/community.crypto/pull/891).

Removed Features (previously deprecated)
----------------------------------------

- All Entrust content is being removed since the Entrust service in currently being sunsetted after the sale of Entrust's Public Certificates Business to Sectigo; see `the announcement with key dates <https://www.entrust.com/tls-certificate-information-center>`__ and `the migration brief for customers <https://www.sectigo.com/uploads/resources/EOL_Migration-Brief-End-Customer.pdf>`__ for details. Since this process will be completed in 2025, we decided to remove all Entrust content from community.general 3.0.0 (https://github.com/ansible-collections/community.crypto/issues/895, https://github.com/ansible-collections/community.crypto/pull/901).
- The collection no longer supports cryptography < 3.3 (https://github.com/ansible-collections/community.crypto/pull/878, https://github.com/ansible-collections/community.crypto/pull/882).
- acme.acme module utils - the ``get_default_argspec()`` function has been removed. Use ``create_default_argspec()`` instead (https://github.com/ansible-collections/community.crypto/pull/873).
- acme.backends module utils - the methods ``get_ordered_csr_identifiers()`` and ``get_cert_information()`` of ``CryptoBackend`` now must be implemented (https://github.com/ansible-collections/community.crypto/pull/873).
- acme.documentation docs fragment - the ``documentation`` docs fragment has been removed. Use both the ``basic`` and ``account`` docs fragments in ``acme`` instead (https://github.com/ansible-collections/community.crypto/pull/873).
- acme_* modules - support for ACME v1 has been removed (https://github.com/ansible-collections/community.crypto/pull/873).
- community.crypto no longer supports Ansible 2.9, ansible-base 2.10, and ansible-core versions 2.11, 2.12, 2.13, 2.14, 2.15, and 2.16. While content from this collection might still work with some older versions of ansible-core, it will not work with any Python version before 3.7 (https://github.com/ansible-collections/community.crypto/pull/870).
- crypto.basic module utils - remove ``CRYPTOGRAPHY_HAS_*`` flags. All tested features are supported since cryptography 3.0 (https://github.com/ansible-collections/community.crypto/pull/878).
- crypto.cryptography_support module utils - remove ``cryptography_serial_number_of_cert()`` helper function (https://github.com/ansible-collections/community.crypto/pull/878).
- crypto.module_backends.common module utils - this module utils has been removed. Use the ``argspec`` module utils instead (https://github.com/ansible-collections/community.crypto/pull/873).
- crypto.support module utils - remove ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/874).
- ecs_certificate - the module has been removed. Please use community.crypto 2.x.y if you need this module (https://github.com/ansible-collections/community.crypto/pull/900).
- ecs_domain - the module has been removed. Please use community.crypto 2.x.y if you need this module (https://github.com/ansible-collections/community.crypto/pull/900).
- execution environment dependencies - remove PyOpenSSL dependency (https://github.com/ansible-collections/community.crypto/pull/874).
- openssl_csr_pipe - the module now ignores check mode and will always behave as if check mode is not active (https://github.com/ansible-collections/community.crypto/pull/873).
- openssl_pkcs12 - support for the ``pyopenssl`` backend has been removed (https://github.com/ansible-collections/community.crypto/pull/873).
- openssl_privatekey_pipe - the module now ignores check mode and will always behave as if check mode is not active (https://github.com/ansible-collections/community.crypto/pull/873).
- time module utils - remove ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/874).
- x509_certificate - the ``entrust`` provider has been removed. Please use community.crypto 2.x.y if you need this provider (https://github.com/ansible-collections/community.crypto/pull/900).
- x509_certificate_pipe - the ``entrust`` provider has been removed. Please use community.crypto 2.x.y if you need this provider (https://github.com/ansible-collections/community.crypto/pull/900).
- x509_certificate_pipe - the module now ignores check mode and will always behave as if check mode is not active (https://github.com/ansible-collections/community.crypto/pull/873).

Bugfixes
--------

- acme_account - make work with CAs that do not accept any account request without External Account Binding data (https://github.com/ansible-collections/community.crypto/issues/918, https://github.com/ansible-collections/community.crypto/pull/919).
- openssl_csr, openssl_csr_pipe - avoid accessing internal members of cryptography's ``KeyUsage`` extension object (https://github.com/ansible-collections/community.crypto/pull/910).

v2.26.1
=======

Release Summary
---------------

Bugfix and maintenance release with improved CI.

Bugfixes
--------

- luks_device - mark parameter ``passphrase_encoding`` as ``no_log=False`` to avoid confusing warning (https://github.com/ansible-collections/community.crypto/pull/867).
- luks_device - removing a specific keyslot with ``remove_keyslot`` caused the module to hang while cryptsetup was waiting for a passphrase from stdin, while the module did not supply one. Since a keyslot is not necessary, do not provide one (https://github.com/ansible-collections/community.crypto/issues/864, https://github.com/ansible-collections/community.crypto/pull/868).

v2.26.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- openssl_pkcs12 - the module now supports ``certificate_content``/``other_certificates_content`` for cases where the data already exists in memory and not yet in a file (https://github.com/ansible-collections/community.crypto/issues/847, https://github.com/ansible-collections/community.crypto/pull/848).

v2.25.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- luks_device - allow passphrases to contain newlines (https://github.com/ansible-collections/community.crypto/pull/844).

v2.24.0
=======

Release Summary
---------------

New feature and bugfix release with multiple new modules. It also deprecates support for older ansible-core and Python versions.

Minor Changes
-------------

- acme_certificate - add options ``order_creation_error_strategy`` and ``order_creation_max_retries`` which allow to configure the error handling behavior if creating a new ACME order fails. This is particularly important when using the ``include_renewal_cert_id`` option, and the default value ``auto`` for ``order_creation_error_strategy`` tries to gracefully handle related errors (https://github.com/ansible-collections/community.crypto/pull/842).
- acme_certificate - allow to chose a profile for certificate generation, in case the CA supports this using Internet-Draft `draft-aaron-acme-profiles <https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/>`__ (https://github.com/ansible-collections/community.crypto/pull/835).
- acme_certificate_renewal_info - add ``exists`` and ``parsable`` return values and ``treat_parsing_error_as_non_existing`` option (https://github.com/ansible-collections/community.crypto/pull/838).

Deprecated Features
-------------------

- Support for ansible-core 2.11, 2.12, 2.13, 2.14, 2.15, and 2.16 is deprecated, and will be removed in the next major release (community.crypto 3.0.0). Some modules might still work with some of these versions afterwards, but we will no longer keep compatibility code that was needed to support them. Note that this means that support for all Python versions before 3.7 will be dropped, also on the target side (https://github.com/ansible-collections/community.crypto/issues/559, https://github.com/ansible-collections/community.crypto/pull/839).
- Support for cryptography < 3.4 is deprecated, and will be removed in the next major release (community.crypto 3.0.0). Some modules might still work with older versions of cryptography, but we will no longer keep compatibility code that was needed to support them (https://github.com/ansible-collections/community.crypto/issues/559, https://github.com/ansible-collections/community.crypto/pull/839).

Bugfixes
--------

- crypto_info - when running the module on Fedora 41 with ``cryptography`` installed from the package repository, the module crashed apparently due to some elliptic curves being removed from libssl against which cryptography is running, which cryptography did not expect (https://github.com/ansible-collections/community.crypto/pull/834).

New Modules
-----------

- community.crypto.acme_certificate_order_create - Create an ACME v2 order.
- community.crypto.acme_certificate_order_finalize - Finalize an ACME v2 order.
- community.crypto.acme_certificate_order_info - Obtain information for an ACME v2 order.
- community.crypto.acme_certificate_order_validate - Validate authorizations of an ACME v2 order.

v2.23.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- acme_certificate - add compatibility for ACME CAs that are not fully RFC8555 compliant and do not provide ``challenges`` in authz objects (https://github.com/ansible-collections/community.crypto/issues/824, https://github.com/ansible-collections/community.crypto/pull/832).
- luks_device - allow to provide passphrases base64-encoded (https://github.com/ansible-collections/community.crypto/issues/827, https://github.com/ansible-collections/community.crypto/pull/829).
- x509_certificate_convert - add new option ``verify_cert_parsable`` which allows to check whether the certificate can actually be parsed (https://github.com/ansible-collections/community.crypto/issues/809, https://github.com/ansible-collections/community.crypto/pull/830).

Deprecated Features
-------------------

- openssl_pkcs12 - the PyOpenSSL based backend is deprecated and will be removed from community.crypto 3.0.0. From that point on you need cryptography 3.0 or newer to use this module (https://github.com/ansible-collections/community.crypto/issues/667, https://github.com/ansible-collections/community.crypto/pull/831).

v2.22.3
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_* modules - when using the OpenSSL backend, explicitly use the UTC timezone in Python code (https://github.com/ansible-collections/community.crypto/pull/811).
- time module utils - fix conversion of naive ``datetime`` objects to UNIX timestamps for Python 3 (https://github.com/ansible-collections/community.crypto/issues/808, https://github.com/ansible-collections/community.crypto/pull/810).

v2.22.2
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_certificate - fix authorization failure when CSR contains SANs with mixed case (https://github.com/ansible-collections/community.crypto/pull/803).

v2.22.1
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_* modules - when querying renewal information, make sure to insert a slash between the base URL and the certificate identifier (https://github.com/ansible-collections/community.crypto/issues/801, https://github.com/ansible-collections/community.crypto/pull/802).
- various modules - pass absolute paths to ``module.atomic_move()`` (https://github.com/ansible/ansible/issues/83950, https://github.com/ansible-collections/community.crypto/pull/799).

v2.22.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- openssl_privatekey, openssl_privatekey_pipe - add default value ``auto`` for ``cipher`` option, which happens to be the only supported value for this option anyway. Therefore it is no longer necessary to specify ``cipher=auto`` when providing ``passphrase`` (https://github.com/ansible-collections/community.crypto/issues/793, https://github.com/ansible-collections/community.crypto/pull/794).

v2.21.1
=======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- When using cryptography >= 43.0.0, use offset-aware ``datetime.datetime`` objects (with timezone UTC) instead of offset-naive UTC timestamps for the ``InvalidityDate`` X.509 CRL extension (https://github.com/ansible-collections/community.crypto/issues/726, https://github.com/ansible-collections/community.crypto/pull/730).

v2.21.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- certificate_complete_chain - add ability to identify Ed25519 and Ed448 complete chains (https://github.com/ansible-collections/community.crypto/pull/777).
- get_certificate - adds ``tls_ctx_options`` option for specifying SSL CTX options (https://github.com/ansible-collections/community.crypto/pull/779).
- get_certificate - allow to obtain the certificate chain sent by the server, and the one used for validation, with the new ``get_certificate_chain`` option. Note that this option only works if the module is run with Python 3.10 or newer (https://github.com/ansible-collections/community.crypto/issues/568, https://github.com/ansible-collections/community.crypto/pull/784).

v2.20.0
=======

Release Summary
---------------

Feature and bugfix release.

The deprecations in this release are only relevant for collections that use shared
code or docs fragments from this collection.

Minor Changes
-------------

- acme_certificate - add ``include_renewal_cert_id`` option to allow requesting renewal of a specific certificate according to the current ACME Renewal Information specification draft (https://github.com/ansible-collections/community.crypto/pull/739).

Deprecated Features
-------------------

- acme documentation fragment - the default ``community.crypto.acme[.documentation]`` docs fragment is deprecated and will be removed from community.crypto 3.0.0. Replace it with both the new ``community.crypto.acme.basic`` and ``community.crypto.acme.account`` fragments (https://github.com/ansible-collections/community.crypto/pull/735).
- acme.backends module utils - the ``get_cert_information()`` method for a ACME crypto backend must be implemented from community.crypto 3.0.0 on (https://github.com/ansible-collections/community.crypto/pull/736).
- crypto.module_backends.common module utils - the ``crypto.module_backends.common`` module utils is deprecated and will be removed from community.crypto 3.0.0. Use the improved ``argspec`` module util instead (https://github.com/ansible-collections/community.crypto/pull/749).

Bugfixes
--------

- x509_crl, x509_certificate, x509_certificate_info - when parsing absolute timestamps which omitted the second count, the first digit of the minutes was used as a one-digit minutes count, and the second digit of the minutes as a one-digit second count (https://github.com/ansible-collections/community.crypto/pull/745).

New Modules
-----------

- community.crypto.acme_ari_info - Retrieves ACME Renewal Information (ARI) for a certificate.
- community.crypto.acme_certificate_deactivate_authz - Deactivate all authz for an ACME v2 order.
- community.crypto.acme_certificate_renewal_info - Determine whether a certificate should be renewed or not.

v2.19.1
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- crypto.math module utils - change return values for ``quick_is_not_prime()`` and ``convert_int_to_bytes(0, 0)`` for special cases that do not appear when using the collection (https://github.com/ansible-collections/community.crypto/pull/733).
- ecs_certificate - fixed ``csr`` option to be empty and allow renewal of a specific certificate according to the Renewal Information specification (https://github.com/ansible-collections/community.crypto/pull/740).
- x509_certificate - since community.crypto 2.19.0 the module was no longer idempotent with respect to ``not_before`` and ``not_after`` times. This is now fixed (https://github.com/ansible-collections/community.crypto/issues/753, https://github.com/ansible-collections/community.crypto/pull/754).

v2.19.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- When using cryptography >= 42.0.0, use offset-aware ``datetime.datetime`` objects (with timezone UTC) instead of offset-naive UTC timestamps (https://github.com/ansible-collections/community.crypto/issues/726, https://github.com/ansible-collections/community.crypto/pull/727).
- openssh_cert - avoid UTC functions deprecated in Python 3.12 when using Python 3 (https://github.com/ansible-collections/community.crypto/pull/727).

Deprecated Features
-------------------

- acme.backends module utils - from community.crypto on, all implementations of ``CryptoBackend`` must override ``get_ordered_csr_identifiers()``. The current default implementation, which simply sorts the result of ``get_csr_identifiers()``, will then be removed (https://github.com/ansible-collections/community.crypto/pull/725).

Bugfixes
--------

- acme_certificate - respect the order of the CNAME and SAN identifiers that are passed on when creating an ACME order (https://github.com/ansible-collections/community.crypto/issues/723, https://github.com/ansible-collections/community.crypto/pull/725).

New Modules
-----------

- community.crypto.x509_certificate_convert - Convert X.509 certificates

v2.18.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- x509_crl - the new option ``serial_numbers`` allow to configure in which format serial numbers can be provided to ``revoked_certificates[].serial_number``. The default is as integers (``serial_numbers=integer``) for backwards compatibility; setting ``serial_numbers=hex-octets`` allows to specify colon-separated hex octet strings like ``00:11:22:FF`` (https://github.com/ansible-collections/community.crypto/issues/687, https://github.com/ansible-collections/community.crypto/pull/715).

Deprecated Features
-------------------

- openssl_csr_pipe, openssl_privatekey_pipe, x509_certificate_pipe - the current behavior of check mode is deprecated and will change in community.crypto 3.0.0. The current behavior is similar to the modules without ``_pipe``: if the object needs to be (re-)generated, only the ``changed`` status is set, but the object is not updated. From community.crypto 3.0.0 on, the modules will ignore check mode and always act as if check mode is not active. This behavior can already achieved now by adding ``check_mode: false`` to the task. If you think this breaks your use-case of this module, please `create an issue in the community.crypto repository <https://github.com/ansible-collections/community.crypto/issues/new/choose>`__ (https://github.com/ansible-collections/community.crypto/issues/712, https://github.com/ansible-collections/community.crypto/pull/714).

Bugfixes
--------

- luks_device - fixed module a bug that prevented using ``remove_keyslot`` with the value ``0`` (https://github.com/ansible-collections/community.crypto/pull/710).
- luks_device - fixed module falsely outputting ``changed=false`` when trying to add a new slot with a key that is already present in another slot. The module now rejects adding keys that are already present in another slot (https://github.com/ansible-collections/community.crypto/pull/710).
- luks_device - fixed testing of LUKS passphrases in when specifying a keyslot for cryptsetup version 2.0.3. The output of this cryptsetup version slightly differs from later versions (https://github.com/ansible-collections/community.crypto/pull/710).

New Plugins
-----------

Filter
~~~~~~

- community.crypto.parse_serial - Convert a serial number as a colon-separated list of hex numbers to an integer
- community.crypto.to_serial - Convert an integer to a colon-separated list of hex numbers

v2.17.1
=======

Release Summary
---------------

Bugfix release for compatibility with cryptography 42.0.0.

Bugfixes
--------

- openssl_dhparam - was using an internal function instead of the public API to load DH param files when using the ``cryptography`` backend. The internal function was removed in cryptography 42.0.0. The module now uses the public API, which has been available since support for DH params was added to cryptography (https://github.com/ansible-collections/community.crypto/pull/698).
- openssl_privatekey_info - ``check_consistency=true`` no longer works for RSA keys with cryptography 42.0.0+ (https://github.com/ansible-collections/community.crypto/pull/701).
- openssl_privatekey_info - ``check_consistency=true`` now reports a warning if it cannot determine consistency (https://github.com/ansible-collections/community.crypto/pull/705).

v2.17.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- luks_device - add allow discards option (https://github.com/ansible-collections/community.crypto/pull/693).

v2.16.2
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_* modules - directly react on bad return data for account creation/retrieval/updating requests (https://github.com/ansible-collections/community.crypto/pull/682).
- acme_* modules - fix improved error reporting in case of socket errors, bad status lines, and unknown connection errors (https://github.com/ansible-collections/community.crypto/pull/684).
- acme_* modules - increase number of retries from 5 to 10 to increase stability with unstable ACME endpoints (https://github.com/ansible-collections/community.crypto/pull/685).
- acme_* modules - make account registration handling more flexible to accept 404 instead of 400 send by DigiCert's ACME endpoint when an account does not exist (https://github.com/ansible-collections/community.crypto/pull/681).

v2.16.1
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_* modules - also retry requests in case of socket errors, bad status lines, and unknown connection errors; improve error messages in these cases (https://github.com/ansible-collections/community.crypto/issues/680).

v2.16.0
=======

Release Summary
---------------

Bugfix release.

Minor Changes
-------------

- luks_devices - add new options ``keyslot``, ``new_keyslot``, and ``remove_keyslot`` to allow adding/removing keys to/from specific keyslots (https://github.com/ansible-collections/community.crypto/pull/664).

Bugfixes
--------

- openssl_pkcs12 - modify autodetect to not detect pyOpenSSL >= 23.3.0, which removed PKCS#12 support (https://github.com/ansible-collections/community.crypto/pull/666).

v2.15.1
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_* modules - correctly handle error documents without ``type`` (https://github.com/ansible-collections/community.crypto/issues/651, https://github.com/ansible-collections/community.crypto/pull/652).

v2.15.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- openssh_keypair - fail when comment cannot be updated (https://github.com/ansible-collections/community.crypto/pull/646).

Deprecated Features
-------------------

- get_certificate - the default ``false`` of the ``asn1_base64`` option is deprecated and will change to ``true`` in community.crypto 3.0.0 (https://github.com/ansible-collections/community.crypto/pull/600).

Bugfixes
--------

- openssh_cert, openssh_keypair - the modules ignored return codes of ``ssh`` and ``ssh-keygen`` in some cases (https://github.com/ansible-collections/community.crypto/issues/645, https://github.com/ansible-collections/community.crypto/pull/646).
- openssh_keypair - fix comment updating for OpenSSH before 6.5 (https://github.com/ansible-collections/community.crypto/pull/646).

New Plugins
-----------

Filter
~~~~~~

- community.crypto.gpg_fingerprint - Retrieve a GPG fingerprint from a GPG public or private key

Lookup
~~~~~~

- community.crypto.gpg_fingerprint - Retrieve a GPG fingerprint from a GPG public or private key file

v2.14.1
=======

Release Summary
---------------

Bugfix and maintenance release with updated documentation.

From this version on, community.crypto is using the new `Ansible semantic markup
<https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_documenting.html#semantic-markup-within-module-documentation>`__
in its documentation. If you look at documentation with the ansible-doc CLI tool
from ansible-core before 2.15, please note that it does not render the markup
correctly. You should be still able to read it in most cases, but you need
ansible-core 2.15 or later to see it as it is intended. Alternatively you can
look at `the devel docsite <https://docs.ansible.com/ansible/devel/collections/community/crypto/>`__
for the rendered HTML version of the documentation of the latest release.

Bugfixes
--------

- Fix PEM detection/identification to also accept random other lines before the line starting with ``-----BEGIN`` (https://github.com/ansible-collections/community.crypto/issues/627, https://github.com/ansible-collections/community.crypto/pull/628).

Known Issues
------------

- Ansible markup will show up in raw form on ansible-doc text output for ansible-core before 2.15. If you have trouble deciphering the documentation markup, please upgrade to ansible-core 2.15 (or newer), or read the HTML documentation on https://docs.ansible.com/ansible/devel/collections/community/crypto/.

v2.14.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- acme_certificate - allow to use no challenge by providing ``no challenge`` for the ``challenge`` option. This is needed for ACME servers where validation is done without challenges (https://github.com/ansible-collections/community.crypto/issues/613, https://github.com/ansible-collections/community.crypto/pull/615).
- acme_certificate - validate and wait for challenges in parallel instead handling them one after another (https://github.com/ansible-collections/community.crypto/pull/617).
- x509_certificate_info - added support for certificates in DER format when using ``path`` parameter (https://github.com/ansible-collections/community.crypto/issues/603).

v2.13.1
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- execution environment definition - fix installation of ``python3-pyOpenSSL`` package on CentOS and RHEL (https://github.com/ansible-collections/community.crypto/pull/606).
- execution environment definition - fix source of ``python3-pyOpenSSL`` package for Rocky Linux 9+ (https://github.com/ansible-collections/community.crypto/pull/606).

v2.13.0
=======

Release Summary
---------------

Bugfix and maintenance release.

Minor Changes
-------------

- x509_crl - the ``crl_mode`` option has been added to replace the existing ``mode`` option (https://github.com/ansible-collections/community.crypto/issues/596).

Deprecated Features
-------------------

- x509_crl - the ``mode`` option is deprecated; use ``crl_mode`` instead. The ``mode`` option will change its meaning in community.crypto 3.0.0, and will refer to the CRL file's mode instead (https://github.com/ansible-collections/community.crypto/issues/596).

Bugfixes
--------

- openssh_keypair - always generate a new key pair if the private key does not exist. Previously, the module would fail when ``regenerate=fail`` without an existing key, contradicting the documentation (https://github.com/ansible-collections/community.crypto/pull/598).
- x509_crl - remove problem with ansible-core 2.16 due to ``AnsibleModule`` is now validating the ``mode`` parameter's values (https://github.com/ansible-collections/community.crypto/issues/596).

v2.12.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- get_certificate - add ``asn1_base64`` option to control whether the ASN.1 included in the ``extensions`` return value is binary data or Base64 encoded (https://github.com/ansible-collections/community.crypto/pull/592).

v2.11.1
=======

Release Summary
---------------

Maintenance release with improved documentation.

v2.11.0
=======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- get_certificate - adds ``ciphers`` option for custom cipher selection (https://github.com/ansible-collections/community.crypto/pull/571).

Bugfixes
--------

- action plugin helper - fix handling of deprecations for ansible-core 2.14.2 (https://github.com/ansible-collections/community.crypto/pull/572).
- execution environment binary dependencies (bindep.txt) - fix ``python3-pyOpenSSL`` dependency resolution on RHEL 9+ / CentOS Stream 9+ platforms (https://github.com/ansible-collections/community.crypto/pull/575).
- various plugins - remove unnecessary imports (https://github.com/ansible-collections/community.crypto/pull/569).

v2.10.0
=======

Release Summary
---------------

Bugfix and feature release.

Bugfixes
--------

- openssl_csr, openssl_csr_pipe - prevent invalid values for ``crl_distribution_points`` that do not have one of ``full_name``, ``relative_name``, and ``crl_issuer`` (https://github.com/ansible-collections/community.crypto/pull/560).
- openssl_publickey_info - do not crash with internal error when public key cannot be parsed (https://github.com/ansible-collections/community.crypto/pull/551).

New Plugins
-----------

Filter
~~~~~~

- community.crypto.openssl_csr_info - Retrieve information from OpenSSL Certificate Signing Requests (CSR)
- community.crypto.openssl_privatekey_info - Retrieve information from OpenSSL private keys
- community.crypto.openssl_publickey_info - Retrieve information from OpenSSL public keys in PEM format
- community.crypto.split_pem - Split PEM file contents into multiple objects
- community.crypto.x509_certificate_info - Retrieve information from X.509 certificates in PEM format
- community.crypto.x509_crl_info - Retrieve information from X.509 CRLs in PEM format

v2.9.0
======

Release Summary
---------------

Regular feature release.

Minor Changes
-------------

- x509_certificate_info - adds ``issuer_uri`` field in return value based on Authority Information Access data (https://github.com/ansible-collections/community.crypto/pull/530).

v2.8.1
======

Release Summary
---------------

Maintenance release with improved documentation.

v2.8.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- acme_* modules - handle more gracefully if CA's new nonce call does not return a nonce (https://github.com/ansible-collections/community.crypto/pull/525).
- acme_* modules - include symbolic HTTP status codes in error and log messages when available (https://github.com/ansible-collections/community.crypto/pull/524).
- openssl_pkcs12 - add option ``encryption_level`` which allows to chose ``compatibility2022`` when cryptography >= 38.0.0 is used to enable a more backwards compatible encryption algorithm. If cryptography uses OpenSSL 3.0.0 or newer, the default algorithm is not compatible with older software (https://github.com/ansible-collections/community.crypto/pull/523).

v2.7.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- acme_* modules - improve feedback when importing ``cryptography`` does not work (https://github.com/ansible-collections/community.crypto/issues/518, https://github.com/ansible-collections/community.crypto/pull/519).

v2.7.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- acme* modules - also support the HTTP 503 Service Unavailable and 408 Request Timeout response status for automatic retries (https://github.com/ansible-collections/community.crypto/pull/513).

Bugfixes
--------

- openssl_privatekey_pipe - ensure compatibility with newer versions of ansible-core (https://github.com/ansible-collections/community.crypto/pull/515).

v2.6.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- acme* modules - support the HTTP 429 Too Many Requests response status (https://github.com/ansible-collections/community.crypto/pull/508).
- openssh_keypair - added ``pkcs1``, ``pkcs8``, and ``ssh`` to the available choices for the ``private_key_format`` option (https://github.com/ansible-collections/community.crypto/pull/511).

v2.5.0
======

Release Summary
---------------

Maintenance release with improved licensing declaration and documentation fixes.

Minor Changes
-------------

- All software licenses are now in the ``LICENSES/`` directory of the collection root. Moreover, ``SPDX-License-Identifier:`` is used to declare the applicable license for every file that is not automatically generated (https://github.com/ansible-collections/community.crypto/pull/491).

v2.4.0
======

Release Summary
---------------

Deprecation and bugfix release. No new features this time.

Deprecated Features
-------------------

- Support for Ansible 2.9 and ansible-base 2.10 is deprecated, and will be removed in the next major release (community.crypto 3.0.0). Some modules might still work with these versions afterwards, but we will no longer keep compatibility code that was needed to support them (https://github.com/ansible-collections/community.crypto/pull/460).

Bugfixes
--------

- openssl_pkcs12 - when using the pyOpenSSL backend, do not crash when trying to read non-existing other certificates (https://github.com/ansible-collections/community.crypto/issues/486, https://github.com/ansible-collections/community.crypto/pull/487).

v2.3.4
======

Release Summary
---------------

Re-release of what was intended to be 2.3.3.

A mistake during the release process caused the 2.3.3 tag to end up on the
commit for 1.9.17, which caused the release pipeline to re-publish 1.9.17
as 2.3.3.

This release is identical to what should have been 2.3.3, except that the
version number has been bumped to 2.3.4 and this changelog entry for 2.3.4
has been added.

v2.3.3
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- Include ``Apache-2.0.txt`` file for ``plugins/module_utils/crypto/_obj2txt.py`` and ``plugins/module_utils/crypto/_objects_data.py``.
- openssl_csr - the module no longer crashes with 'permitted_subtrees/excluded_subtrees must be a non-empty list or None' if only one of ``name_constraints_permitted`` and ``name_constraints_excluded`` is provided (https://github.com/ansible-collections/community.crypto/issues/481).
- x509_crl - do not crash when signing CRL with Ed25519 or Ed448 keys (https://github.com/ansible-collections/community.crypto/issues/473, https://github.com/ansible-collections/community.crypto/pull/474).

v2.3.2
======

Release Summary
---------------

Maintenance and bugfix release.

Bugfixes
--------

- Include ``simplified_bsd.txt`` license file for the ECS module utils.
- certificate_complete_chain - do not stop execution if an unsupported signature algorithm is encountered; warn instead (https://github.com/ansible-collections/community.crypto/pull/457).

v2.3.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Include ``PSF-license.txt`` file for ``plugins/module_utils/_version.py``.

v2.3.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- Prepare collection for inclusion in an Execution Environment by declaring its dependencies. Please note that system packages are used for cryptography and PyOpenSSL, which can be rather limited. If you need features from newer cryptography versions, you will have to manually force a newer version to be installed by pip by specifying something like ``cryptography >= 37.0.0`` in your Execution Environment's Python dependencies file (https://github.com/ansible-collections/community.crypto/pull/440).
- Support automatic conversion for Internalionalized Domain Names (IDNs). When passing general names, for example Subject Alternative Names to ``community.crypto.openssl_csr``, these will automatically be converted to IDNA. Conversion will be done per label to IDNA2008 if possible, and IDNA2003 if IDNA2008 conversion fails for that label. Note that IDNA conversion requires `the Python idna library <https://pypi.org/project/idna/>`_ to be installed. Please note that depending on which versions of the cryptography library are used, it could try to process the converted IDNA another time with the Python ``idna`` library and reject IDNA2003 encoded values. Using a new enough ``cryptography`` version avoids this (https://github.com/ansible-collections/community.crypto/issues/426, https://github.com/ansible-collections/community.crypto/pull/436).
- acme_* modules - add parameter ``request_timeout`` to manage HTTP(S) request timeout (https://github.com/ansible-collections/community.crypto/issues/447, https://github.com/ansible-collections/community.crypto/pull/448).
- luks_devices - added ``perf_same_cpu_crypt``, ``perf_submit_from_crypt_cpus``, ``perf_no_read_workqueue``, ``perf_no_write_workqueue`` for performance tuning when opening LUKS2 containers (https://github.com/ansible-collections/community.crypto/issues/427).
- luks_devices - added ``persistent`` option when opening LUKS2 containers (https://github.com/ansible-collections/community.crypto/pull/434).
- openssl_csr_info - add ``name_encoding`` option to control the encoding (IDNA, Unicode) used to return domain names in general names (https://github.com/ansible-collections/community.crypto/pull/436).
- openssl_pkcs12 - allow to provide the private key as text instead of having to read it from a file. This allows to store the private key in an encrypted form, for example in Ansible Vault (https://github.com/ansible-collections/community.crypto/pull/452).
- x509_certificate_info - add ``name_encoding`` option to control the encoding (IDNA, Unicode) used to return domain names in general names (https://github.com/ansible-collections/community.crypto/pull/436).
- x509_crl - add ``name_encoding`` option to control the encoding (IDNA, Unicode) used to return domain names in general names (https://github.com/ansible-collections/community.crypto/pull/436).
- x509_crl_info - add ``name_encoding`` option to control the encoding (IDNA, Unicode) used to return domain names in general names (https://github.com/ansible-collections/community.crypto/pull/436).

Bugfixes
--------

- Make collection more robust when PyOpenSSL is used with an incompatible cryptography version (https://github.com/ansible-collections/community.crypto/pull/445).
- x509_crl - fix crash when ``issuer`` for a revoked certificate is specified (https://github.com/ansible-collections/community.crypto/pull/441).

v2.2.4
======

Release Summary
---------------

Regular maintenance release.

Bugfixes
--------

- openssh_* modules - fix exception handling to report traceback to users for enhanced traceability (https://github.com/ansible-collections/community.crypto/pull/417).

v2.2.3
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- luks_device - fix parsing of ``lsblk`` output when device name ends with ``crypt`` (https://github.com/ansible-collections/community.crypto/issues/409, https://github.com/ansible-collections/community.crypto/pull/410).

v2.2.2
======

Release Summary
---------------

Regular bugfix release.

In this release, we extended the test matrix to include Alpine 3, ArchLinux, Debian Bullseye, and CentOS Stream 8. CentOS 8 was removed from the test matrix.

Bugfixes
--------

- certificate_complete_chain - allow multiple potential intermediate certificates to have the same subject (https://github.com/ansible-collections/community.crypto/issues/399, https://github.com/ansible-collections/community.crypto/pull/403).
- x509_certificate - for the ``ownca`` provider, check whether the CA private key actually belongs to the CA certificate (https://github.com/ansible-collections/community.crypto/pull/407).
- x509_certificate - regenerate certificate when the CA's public key changes for ``provider=ownca`` (https://github.com/ansible-collections/community.crypto/pull/407).
- x509_certificate - regenerate certificate when the CA's subject changes for ``provider=ownca`` (https://github.com/ansible-collections/community.crypto/issues/400, https://github.com/ansible-collections/community.crypto/pull/402).
- x509_certificate - regenerate certificate when the private key changes for ``provider=selfsigned`` (https://github.com/ansible-collections/community.crypto/pull/407).

v2.2.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- openssh_cert - fixed false ``changed`` status for ``host`` certificates when using ``full_idempotence`` (https://github.com/ansible-collections/community.crypto/issues/395, https://github.com/ansible-collections/community.crypto/pull/396).

v2.2.0
======

Release Summary
---------------

Regular bugfix and feature release.

Minor Changes
-------------

- openssh_cert - added ``ignore_timestamps`` parameter so it can be used semi-idempotent with relative timestamps in ``valid_to``/``valid_from`` (https://github.com/ansible-collections/community.crypto/issues/379).

Bugfixes
--------

- luks_devices - set ``LANG`` and similar environment variables to avoid translated output, which can break some of the module's functionality like key management (https://github.com/ansible-collections/community.crypto/pull/388, https://github.com/ansible-collections/community.crypto/issues/385).

v2.1.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- Adjust error messages that indicate ``cryptography`` is not installed from ``Can't`` to ``Cannot`` (https://github.com/ansible-collections/community.crypto/pull/374).

Bugfixes
--------

- Various modules and plugins - use vendored version of ``distutils.version`` instead of the deprecated Python standard library ``distutils`` (https://github.com/ansible-collections/community.crypto/pull/353).
- certificate_complete_chain - do not append root twice if the chain already ends with a root certificate (https://github.com/ansible-collections/community.crypto/pull/360).
- certificate_complete_chain - do not hang when infinite loop is found (https://github.com/ansible-collections/community.crypto/issues/355, https://github.com/ansible-collections/community.crypto/pull/360).

New Modules
-----------

- community.crypto.crypto_info - Retrieve cryptographic capabilities
- community.crypto.openssl_privatekey_convert - Convert OpenSSL private keys

v2.0.2
======

Release Summary
---------------

Documentation fix release. No actual code changes.

v2.0.1
======

Release Summary
---------------

Bugfix release with extra forward compatibility for newer versions of cryptography.

Minor Changes
-------------

- acme_* modules - fix usage of ``fetch_url`` with changes in latest ansible-core ``devel`` branch (https://github.com/ansible-collections/community.crypto/pull/339).

Bugfixes
--------

- acme_certificate - avoid passing multiple certificates to ``cryptography``'s X.509 certificate loader when ``fullchain_dest`` is used (https://github.com/ansible-collections/community.crypto/pull/324).
- get_certificate, openssl_csr_info, x509_certificate_info - add fallback code for extension parsing that works with cryptography 36.0.0 and newer. This code re-serializes de-serialized extensions and thus can return slightly different values if the extension in the original CSR resp. certificate was not canonicalized correctly. This code is currently used as a fallback if the existing code stops working, but we will switch it to be the main code in a future release (https://github.com/ansible-collections/community.crypto/pull/331).
- luks_device - now also runs a built-in LUKS signature cleaner on ``state=absent`` to make sure that also the secondary LUKS2 header is wiped when older versions of wipefs are used (https://github.com/ansible-collections/community.crypto/issues/326, https://github.com/ansible-collections/community.crypto/pull/327).
- openssl_pkcs12 - use new PKCS#12 deserialization infrastructure from cryptography 36.0.0 if available (https://github.com/ansible-collections/community.crypto/pull/302).

v2.0.0
======

Release Summary
---------------

A new major release of the ``community.crypto`` collection. The main changes are removal of the PyOpenSSL backends for almost all modules (``openssl_pkcs12`` being the only exception), and removal of the ``assertonly`` provider in the ``x509_certificate`` provider. There are also some other breaking changes which should improve the user interface/experience of this collection long-term.

Minor Changes
-------------

- acme_certificate - the ``subject`` and ``issuer`` fields in in the ``select_chain`` entries are now more strictly validated (https://github.com/ansible-collections/community.crypto/pull/316).
- openssl_csr, openssl_csr_pipe - provide a new ``subject_ordered`` option if the order of the components in the subject is of importance (https://github.com/ansible-collections/community.crypto/issues/291, https://github.com/ansible-collections/community.crypto/pull/316).
- openssl_csr, openssl_csr_pipe - there is now stricter validation of the values of the ``subject`` option (https://github.com/ansible-collections/community.crypto/pull/316).
- openssl_privatekey_info - add ``check_consistency`` option to request private key consistency checks to be done (https://github.com/ansible-collections/community.crypto/pull/309).
- x509_certificate, x509_certificate_pipe - add ``ignore_timestamps`` option which allows to enable idempotency for 'not before' and 'not after' options (https://github.com/ansible-collections/community.crypto/issues/295, https://github.com/ansible-collections/community.crypto/pull/317).
- x509_crl - provide a new ``issuer_ordered`` option if the order of the components in the issuer is of importance (https://github.com/ansible-collections/community.crypto/issues/291, https://github.com/ansible-collections/community.crypto/pull/316).
- x509_crl - there is now stricter validation of the values of the ``issuer`` option (https://github.com/ansible-collections/community.crypto/pull/316).

Breaking Changes / Porting Guide
--------------------------------

- Adjust ``dirName`` text parsing and to text converting code to conform to `Sections 2 and 3 of RFC 4514 <https://datatracker.ietf.org/doc/html/rfc4514.html>`_. This is similar to how `cryptography handles this <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Name.rfc4514_string>`_ (https://github.com/ansible-collections/community.crypto/pull/274).
- acme module utils - removing compatibility code (https://github.com/ansible-collections/community.crypto/pull/290).
- acme_* modules - removed vendored copy of the Python library ``ipaddress``. If you are using Python 2.x, please make sure to install the library (https://github.com/ansible-collections/community.crypto/pull/287).
- compatibility module_utils - removed vendored copy of the Python library ``ipaddress`` (https://github.com/ansible-collections/community.crypto/pull/287).
- crypto module utils - removing compatibility code (https://github.com/ansible-collections/community.crypto/pull/290).
- get_certificate, openssl_csr_info, x509_certificate_info - depending on the ``cryptography`` version used, the modules might not return the ASN.1 value for an extension as contained in the certificate respectively CSR, but a re-encoded version of it. This should usually be identical to the value contained in the source file, unless the value was malformed. For extensions not handled by C(cryptography) the value contained in the source file is always returned unaltered (https://github.com/ansible-collections/community.crypto/pull/318).
- module_utils - removed various PyOpenSSL support functions and default backend values that are not needed for the openssl_pkcs12 module (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_csr, openssl_csr_pipe, x509_crl - the ``subject`` respectively ``issuer`` fields no longer ignore empty values, but instead fail when encountering them (https://github.com/ansible-collections/community.crypto/pull/316).
- openssl_privatekey_info - by default consistency checks are not run; they need to be explicitly requested by passing ``check_consistency=true`` (https://github.com/ansible-collections/community.crypto/pull/309).
- x509_crl - for idempotency checks, the ``issuer`` order is ignored. If order is important, use the new ``issuer_ordered`` option (https://github.com/ansible-collections/community.crypto/pull/316).

Deprecated Features
-------------------

- acme_* modules - ACME version 1 is now deprecated and support for it will be removed in community.crypto 2.0.0 (https://github.com/ansible-collections/community.crypto/pull/288).

Removed Features (previously deprecated)
----------------------------------------

- acme_* modules - the ``acme_directory`` option is now required (https://github.com/ansible-collections/community.crypto/pull/290).
- acme_* modules - the ``acme_version`` option is now required (https://github.com/ansible-collections/community.crypto/pull/290).
- acme_account_facts - the deprecated redirect has been removed. Use community.crypto.acme_account_info instead (https://github.com/ansible-collections/community.crypto/pull/290).
- acme_account_info - ``retrieve_orders=url_list`` no longer returns the return value ``orders``. Use the ``order_uris`` return value instead (https://github.com/ansible-collections/community.crypto/pull/290).
- crypto.info module utils - the deprecated redirect has been removed. Use ``crypto.pem`` instead (https://github.com/ansible-collections/community.crypto/pull/290).
- get_certificate - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_certificate - the deprecated redirect has been removed. Use community.crypto.x509_certificate instead (https://github.com/ansible-collections/community.crypto/pull/290).
- openssl_certificate_info - the deprecated redirect has been removed. Use community.crypto.x509_certificate_info instead (https://github.com/ansible-collections/community.crypto/pull/290).
- openssl_csr - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_csr and openssl_csr_pipe - ``version`` now only accepts the (default) value 1 (https://github.com/ansible-collections/community.crypto/pull/290).
- openssl_csr_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_csr_pipe - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_privatekey - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_privatekey_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_privatekey_pipe - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_publickey - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_publickey_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_signature - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_signature_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- x509_certificate - remove ``assertonly`` provider (https://github.com/ansible-collections/community.crypto/pull/289).
- x509_certificate - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- x509_certificate_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- x509_certificate_pipe - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).

Bugfixes
--------

- cryptography backend - improve Unicode handling for Python 2 (https://github.com/ansible-collections/community.crypto/pull/313).
- get_certificate - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).
- openssl_csr_info - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).
- openssl_pkcs12 - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/296).
- x509_certificate_info - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).

v1.9.4
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- acme_* modules - fix commands composed for OpenSSL backend to retrieve information on CSRs and certificates from stdin to use ``/dev/stdin`` instead of ``-``. This is needed for OpenSSL 1.0.1 and 1.0.2, apparently (https://github.com/ansible-collections/community.crypto/pull/279).
- acme_challenge_cert_helper - only return exception when cryptography is not installed, not when a too old version of it is installed. This prevents Ansible's callback to crash (https://github.com/ansible-collections/community.crypto/pull/281).

v1.9.3
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- openssl_csr and openssl_csr_pipe - make sure that Unicode strings are used to compare strings with the cryptography backend. This fixes idempotency problems with non-ASCII letters on Python 2 (https://github.com/ansible-collections/community.crypto/issues/270, https://github.com/ansible-collections/community.crypto/pull/271).

v1.9.2
======

Release Summary
---------------

Bugfix release to fix the changelog. No other change compared to 1.9.0.

v1.9.1
======

Release Summary
---------------

Accidental 1.9.1 release. Identical to 1.9.0.

v1.9.0
======

Release Summary
---------------

Regular feature release.

Minor Changes
-------------

- get_certificate - added ``starttls`` option to retrieve certificates from servers which require clients to request an encrypted connection (https://github.com/ansible-collections/community.crypto/pull/264).
- openssh_keypair - added ``diff`` support (https://github.com/ansible-collections/community.crypto/pull/260).

Bugfixes
--------

- keypair_backend module utils - simplify code to pass sanity tests (https://github.com/ansible-collections/community.crypto/pull/263).
- openssh_keypair - fixed ``cryptography`` backend to preserve original file permissions when regenerating a keypair requires existing files to be overwritten (https://github.com/ansible-collections/community.crypto/pull/260).
- openssh_keypair - fixed error handling to restore original keypair if regeneration fails (https://github.com/ansible-collections/community.crypto/pull/260).
- x509_crl - restore inherited function signature to pass sanity tests (https://github.com/ansible-collections/community.crypto/pull/263).

v1.8.0
======

Release Summary
---------------

Regular bugfix and feature release.

Minor Changes
-------------

- Avoid internal ansible-core module_utils in favor of equivalent public API available since at least Ansible 2.9 (https://github.com/ansible-collections/community.crypto/pull/253).
- openssh certificate module utils - new module_utils for parsing OpenSSH certificates (https://github.com/ansible-collections/community.crypto/pull/246).
- openssh_cert - added ``regenerate`` option to validate additional certificate parameters which trigger regeneration of an existing certificate (https://github.com/ansible-collections/community.crypto/pull/256).
- openssh_cert - adding ``diff`` support (https://github.com/ansible-collections/community.crypto/pull/255).

Bugfixes
--------

- openssh_cert - fixed certificate generation to restore original certificate if an error is encountered (https://github.com/ansible-collections/community.crypto/pull/255).
- openssh_keypair - fixed a bug that prevented custom file attributes being applied to public keys (https://github.com/ansible-collections/community.crypto/pull/257).

v1.7.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- openssl_pkcs12 - fix crash when loading passphrase-protected PKCS#12 files with ``cryptography`` backend (https://github.com/ansible-collections/community.crypto/issues/247, https://github.com/ansible-collections/community.crypto/pull/248).

v1.7.0
======

Release Summary
---------------

Regular feature and bugfix release.

Minor Changes
-------------

- cryptography_openssh module utils - new module_utils for managing asymmetric keypairs and OpenSSH formatted/encoded asymmetric keypairs (https://github.com/ansible-collections/community.crypto/pull/213).
- openssh_keypair - added ``backend`` parameter for selecting between the cryptography library or the OpenSSH binary for the execution of actions performed by ``openssh_keypair`` (https://github.com/ansible-collections/community.crypto/pull/236).
- openssh_keypair - added ``passphrase`` parameter for encrypting/decrypting OpenSSH private keys (https://github.com/ansible-collections/community.crypto/pull/225).
- openssl_csr - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- openssl_csr_info - now returns ``public_key_type`` and ``public_key_data`` (https://github.com/ansible-collections/community.crypto/pull/233).
- openssl_csr_info - refactor module to allow code reuse for diff mode (https://github.com/ansible-collections/community.crypto/pull/204).
- openssl_csr_pipe - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- openssl_pkcs12 - added option ``select_crypto_backend`` and a ``cryptography`` backend. This requires cryptography 3.0 or newer, and does not support the ``iter_size`` and ``maciter_size`` options (https://github.com/ansible-collections/community.crypto/pull/234).
- openssl_privatekey - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- openssl_privatekey_info - refactor module to allow code reuse for diff mode (https://github.com/ansible-collections/community.crypto/pull/205).
- openssl_privatekey_pipe - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- openssl_publickey - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- x509_certificate - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- x509_certificate_info - now returns ``public_key_type`` and ``public_key_data`` (https://github.com/ansible-collections/community.crypto/pull/233).
- x509_certificate_info - refactor module to allow code reuse for diff mode (https://github.com/ansible-collections/community.crypto/pull/206).
- x509_certificate_pipe - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- x509_crl - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- x509_crl_info - add ``list_revoked_certificates`` option to avoid enumerating all revoked certificates (https://github.com/ansible-collections/community.crypto/pull/232).
- x509_crl_info - refactor module to allow code reuse for diff mode (https://github.com/ansible-collections/community.crypto/pull/203).

Bugfixes
--------

- openssh_keypair - fix ``check_mode`` to populate return values for existing keypairs (https://github.com/ansible-collections/community.crypto/issues/113, https://github.com/ansible-collections/community.crypto/pull/230).
- various modules - prevent crashes when modules try to set attributes on not yet existing files in check mode. This will be fixed in ansible-core 2.12, but it is not backported to every Ansible version we support (https://github.com/ansible-collections/community.crypto/issue/242, https://github.com/ansible-collections/community.crypto/pull/243).
- x509_certificate - fix crash when ``assertonly`` provider is used and some error conditions should be reported (https://github.com/ansible-collections/community.crypto/issues/240, https://github.com/ansible-collections/community.crypto/pull/241).

New Modules
-----------

- community.crypto.openssl_publickey_info - Provide information for OpenSSL public keys

v1.6.2
======

Release Summary
---------------

Bugfix release. Fixes compatibility issue of ACME modules with step-ca.

Bugfixes
--------

- acme_* modules - avoid crashing for ACME servers where the ``meta`` directory key is not present (https://github.com/ansible-collections/community.crypto/issues/220, https://github.com/ansible-collections/community.crypto/pull/221).

v1.6.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_* modules - fix wrong usages of ``ACMEProtocolException`` (https://github.com/ansible-collections/community.crypto/pull/216, https://github.com/ansible-collections/community.crypto/pull/217).

v1.6.0
======

Release Summary
---------------

Fixes compatibility issues with the latest ansible-core 2.11 beta, and contains a lot of internal refactoring for the ACME modules and support for private key passphrases for them.

Minor Changes
-------------

- acme module_utils - the ``acme`` module_utils has been split up into several Python modules (https://github.com/ansible-collections/community.crypto/pull/184).
- acme_* modules - codebase refactor which should not be visible to end-users (https://github.com/ansible-collections/community.crypto/pull/184).
- acme_* modules - support account key passphrases for ``cryptography`` backend (https://github.com/ansible-collections/community.crypto/issues/197, https://github.com/ansible-collections/community.crypto/pull/207).
- acme_certificate_revoke - support revoking by private keys that are passphrase protected for ``cryptography`` backend (https://github.com/ansible-collections/community.crypto/pull/207).
- acme_challenge_cert_helper - add ``private_key_passphrase`` parameter (https://github.com/ansible-collections/community.crypto/pull/207).

Deprecated Features
-------------------

- acme module_utils - the ``acme`` module_utils (``ansible_collections.community.crypto.plugins.module_utils.acme``) is deprecated and will be removed in community.crypto 2.0.0. Use the new Python modules in the ``acme`` package instead (``ansible_collections.community.crypto.plugins.module_utils.acme.xxx``) (https://github.com/ansible-collections/community.crypto/pull/184).

Bugfixes
--------

- action_module plugin helper - make compatible with latest changes in ansible-core 2.11.0b3 (https://github.com/ansible-collections/community.crypto/pull/202).
- openssl_privatekey_pipe - make compatible with latest changes in ansible-core 2.11.0b3 (https://github.com/ansible-collections/community.crypto/pull/202).

v1.5.0
======

Release Summary
---------------

Regular feature and bugfix release. Deprecates a return value.

Minor Changes
-------------

- acme_account_info - when ``retrieve_orders`` is not ``ignore`` and the ACME server allows to query orders, the new return value ``order_uris`` is always populated with a list of URIs (https://github.com/ansible-collections/community.crypto/pull/178).
- luks_device - allow to specify sector size for LUKS2 containers with new ``sector_size`` parameter (https://github.com/ansible-collections/community.crypto/pull/193).

Deprecated Features
-------------------

- acme_account_info - when ``retrieve_orders=url_list``, ``orders`` will no longer be returned in community.crypto 2.0.0. Use ``order_uris`` instead (https://github.com/ansible-collections/community.crypto/pull/178).

Bugfixes
--------

- openssl_csr - no longer fails when comparing CSR without basic constraint when ``basic_constraints`` is specified (https://github.com/ansible-collections/community.crypto/issues/179, https://github.com/ansible-collections/community.crypto/pull/180).

v1.4.0
======

Release Summary
---------------

Release with several new features and bugfixes.

Minor Changes
-------------

- The ACME module_utils has been relicensed back from the Simplified BSD License (https://opensource.org/licenses/BSD-2-Clause) to the GPLv3+ (same license used by most other code in this collection). This undoes a licensing change when the original GPLv3+ licensed code was moved to module_utils in https://github.com/ansible/ansible/pull/40697 (https://github.com/ansible-collections/community.crypto/pull/165).
- The ``crypto/identify.py`` module_utils has been renamed to ``crypto/pem.py`` (https://github.com/ansible-collections/community.crypto/pull/166).
- luks_device - ``new_keyfile``, ``new_passphrase``, ``remove_keyfile`` and ``remove_passphrase`` are now idempotent (https://github.com/ansible-collections/community.crypto/issues/19, https://github.com/ansible-collections/community.crypto/pull/168).
- luks_device - allow to configure PBKDF (https://github.com/ansible-collections/community.crypto/pull/163).
- openssl_csr, openssl_csr_pipe - allow to specify CRL distribution endpoints with ``crl_distribution_points`` (https://github.com/ansible-collections/community.crypto/issues/147, https://github.com/ansible-collections/community.crypto/pull/167).
- openssl_pkcs12 - allow to specify certificate bundles in ``other_certificates`` by using new option ``other_certificates_parse_all`` (https://github.com/ansible-collections/community.crypto/issues/149, https://github.com/ansible-collections/community.crypto/pull/166).

Bugfixes
--------

- acme_certificate - error when requested challenge type is not found for non-valid challenges, instead of hanging on step 2 (https://github.com/ansible-collections/community.crypto/issues/171, https://github.com/ansible-collections/community.crypto/pull/173).

v1.3.0
======

Release Summary
---------------

Contains new modules ``openssl_privatekey_pipe``, ``openssl_csr_pipe`` and ``x509_certificate_pipe`` which allow to create or update private keys, CSRs and X.509 certificates without having to write them to disk.

Minor Changes
-------------

- openssh_cert - add module parameter ``use_agent`` to enable using signing keys stored in ssh-agent (https://github.com/ansible-collections/community.crypto/issues/116).
- openssl_csr - refactor module to allow code reuse by openssl_csr_pipe (https://github.com/ansible-collections/community.crypto/pull/123).
- openssl_privatekey - refactor module to allow code reuse by openssl_privatekey_pipe (https://github.com/ansible-collections/community.crypto/pull/119).
- openssl_privatekey - the elliptic curve ``secp192r1`` now triggers a security warning. Elliptic curves of at least 224 bits should be used for new keys; see `here <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec.html#elliptic-curves>`_ (https://github.com/ansible-collections/community.crypto/pull/132).
- x509_certificate - for the ``selfsigned`` provider, a CSR is not required anymore. If no CSR is provided, the module behaves as if a minimal CSR which only contains the public key has been provided (https://github.com/ansible-collections/community.crypto/issues/32, https://github.com/ansible-collections/community.crypto/pull/129).
- x509_certificate - refactor module to allow code reuse by x509_certificate_pipe (https://github.com/ansible-collections/community.crypto/pull/135).

Bugfixes
--------

- openssl_pkcs12 - report the correct state when ``action`` is ``parse`` (https://github.com/ansible-collections/community.crypto/issues/143).
- support code - improve handling of certificate and certificate signing request (CSR) loading with the ``cryptography`` backend when errors occur (https://github.com/ansible-collections/community.crypto/issues/138, https://github.com/ansible-collections/community.crypto/pull/139).
- x509_certificate - fix ``entrust`` provider, which was broken since community.crypto 0.1.0 due to a feature added before the collection move (https://github.com/ansible-collections/community.crypto/pull/135).

New Modules
-----------

- community.crypto.openssl_csr_pipe - Generate OpenSSL Certificate Signing Request (CSR)
- community.crypto.openssl_privatekey_pipe - Generate OpenSSL private keys without disk access
- community.crypto.x509_certificate_pipe - Generate and/or check OpenSSL certificates

v1.2.0
======

Release Summary
---------------

Please note that this release fixes a security issue (CVE-2020-25646).

Minor Changes
-------------

- acme_certificate - allow to pass CSR file as content with new option ``csr_content`` (https://github.com/ansible-collections/community.crypto/pull/115).
- x509_certificate_info - add ``fingerprints`` return value which returns certificate fingerprints (https://github.com/ansible-collections/community.crypto/pull/121).

Security Fixes
--------------

- openssl_csr - the option ``privatekey_content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- openssl_privatekey_info - the option ``content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- openssl_publickey - the option ``privatekey_content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- openssl_signature - the option ``privatekey_content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- x509_certificate - the options ``privatekey_content`` and ``ownca_privatekey_content`` were not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- x509_crl - the option ``privatekey_content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).

Bugfixes
--------

- openssl_pkcs12 - do not crash when reading PKCS#12 file which has no private key and/or no main certificate (https://github.com/ansible-collections/community.crypto/issues/103).

v1.1.1
======

Release Summary
---------------

Bugfixes for Ansible 2.10.0.

Bugfixes
--------

- meta/runtime.yml - convert Ansible version numbers for old names of modules to collection version numbers (https://github.com/ansible-collections/community.crypto/pull/108).
- openssl_csr - improve handling of IDNA errors (https://github.com/ansible-collections/community.crypto/issues/105).

v1.1.0
======

Release Summary
---------------

Release for Ansible 2.10.0.

Minor Changes
-------------

- acme_account - add ``external_account_binding`` option to allow creation of ACME accounts with External Account Binding (https://github.com/ansible-collections/community.crypto/issues/89).
- acme_certificate - allow new selector ``test_certificates: first`` for ``select_chain`` parameter (https://github.com/ansible-collections/community.crypto/pull/102).
- cryptography backends - support arbitrary dotted OIDs (https://github.com/ansible-collections/community.crypto/issues/39).
- get_certificate - add support for SNI (https://github.com/ansible-collections/community.crypto/issues/69).
- luks_device - add support for encryption options on container creation (https://github.com/ansible-collections/community.crypto/pull/97).
- openssh_cert - add support for PKCS#11 tokens (https://github.com/ansible-collections/community.crypto/pull/95).
- openssl_certificate - the PyOpenSSL backend now uses 160 bits of randomness for serial numbers, instead of a random number between 1000 and 99999. Please note that this is not a high quality random number (https://github.com/ansible-collections/community.crypto/issues/76).
- openssl_csr - add support for name constraints extension (https://github.com/ansible-collections/community.crypto/issues/46).
- openssl_csr_info - add support for name constraints extension (https://github.com/ansible-collections/community.crypto/issues/46).

Bugfixes
--------

- acme_inspect - fix problem with Python 3.5 that JSON was not decoded (https://github.com/ansible-collections/community.crypto/issues/86).
- get_certificate - fix ``ca_cert`` option handling when ``proxy_host`` is used (https://github.com/ansible-collections/community.crypto/pull/84).
- openssl_*, x509_* modules - fix handling of general names which refer to IP networks and not IP addresses (https://github.com/ansible-collections/community.crypto/pull/92).

New Modules
-----------

- community.crypto.openssl_signature - Sign data with openssl
- community.crypto.openssl_signature_info - Verify signatures with openssl

v1.0.0
======

Release Summary
---------------

This is the first proper release of the ``community.crypto`` collection. This changelog contains all changes to the modules in this collection that were added after the release of Ansible 2.9.0.

Minor Changes
-------------

- luks_device - accept ``passphrase``, ``new_passphrase`` and ``remove_passphrase``.
- luks_device - add ``keysize`` parameter to set key size at LUKS container creation
- luks_device - added support to use UUIDs, and labels with LUKS2 containers
- luks_device - added the ``type`` option that allows user explicit define the LUKS container format version
- openssh_keypair - instead of regenerating some broken or password protected keys, fail the module. Keys can still be regenerated by calling the module with ``force=yes``.
- openssh_keypair - the ``regenerate`` option allows to configure the module's behavior when it should or needs to regenerate private keys.
- openssl_* modules - the cryptography backend now properly supports ``dirName``, ``otherName`` and ``RID`` (Registered ID) names.
- openssl_certificate - Add option for changing which ACME directory to use with acme-tiny. Set the default ACME directory to Let's Encrypt instead of using acme-tiny's default. (acme-tiny also uses Let's Encrypt at the time being, so no action should be necessary.)
- openssl_certificate - Change the required version of acme-tiny to >= 4.0.0
- openssl_certificate - allow to provide content of some input files via the ``csr_content``, ``privatekey_content``, ``ownca_privatekey_content`` and ``ownca_content`` options.
- openssl_certificate - allow to return the existing/generated certificate directly as ``certificate`` by setting ``return_content`` to ``yes``.
- openssl_certificate_info - allow to provide certificate content via ``content`` option (https://github.com/ansible/ansible/issues/64776).
- openssl_csr - Add support for specifying the SAN ``otherName`` value in the OpenSSL ASN.1 UTF8 string format, ``otherName:<OID>;UTF8:string value``.
- openssl_csr - allow to provide private key content via ``private_key_content`` option.
- openssl_csr - allow to return the existing/generated CSR directly as ``csr`` by setting ``return_content`` to ``yes``.
- openssl_csr_info - allow to provide CSR content via ``content`` option.
- openssl_dhparam - allow to return the existing/generated DH params directly as ``dhparams`` by setting ``return_content`` to ``yes``.
- openssl_dhparam - now supports a ``cryptography``-based backend. Auto-detection can be overwritten with the ``select_crypto_backend`` option.
- openssl_pkcs12 - allow to return the existing/generated PKCS#12 directly as ``pkcs12`` by setting ``return_content`` to ``yes``.
- openssl_privatekey - add ``format`` and ``format_mismatch`` options.
- openssl_privatekey - allow to return the existing/generated private key directly as ``privatekey`` by setting ``return_content`` to ``yes``.
- openssl_privatekey - the ``regenerate`` option allows to configure the module's behavior when it should or needs to regenerate private keys.
- openssl_privatekey_info - allow to provide private key content via ``content`` option.
- openssl_publickey - allow to provide private key content via ``private_key_content`` option.
- openssl_publickey - allow to return the existing/generated public key directly as ``publickey`` by setting ``return_content`` to ``yes``.

Deprecated Features
-------------------

- openssl_csr - all values for the ``version`` option except ``1`` are deprecated. The value 1 denotes the current only standardized CSR version.

Removed Features (previously deprecated)
----------------------------------------

- The ``letsencrypt`` module has been removed. Use ``acme_certificate`` instead.

Bugfixes
--------

- ACME modules: fix bug in ACME v1 account update code
- ACME modules: make sure some connection errors are handled properly
- ACME modules: support Buypass' ACME v1 endpoint
- acme_certificate - fix crash when module is used with Python 2.x.
- acme_certificate - fix misbehavior when ACME v1 is used with ``modify_account`` set to ``false``.
- ecs_certificate - Always specify header ``connection: keep-alive`` for ECS API connections.
- ecs_certificate - Fix formatting of contents of ``full_chain_path``.
- get_certificate - Fix cryptography backend when pyopenssl is unavailable (https://github.com/ansible/ansible/issues/67900)
- openssh_keypair - add logic to avoid breaking password protected keys.
- openssh_keypair - fixes idempotence issue with public key (https://github.com/ansible/ansible/issues/64969).
- openssh_keypair - public key's file attributes (permissions, owner, group, etc.) are now set to the same values as the private key.
- openssl_* modules - prevent crash on fingerprint determination in FIPS mode (https://github.com/ansible/ansible/issues/67213).
- openssl_certificate - When provider is ``entrust``, use a ``connection: keep-alive`` header for ECS API connections.
- openssl_certificate - ``provider`` option was documented as required, but it was not checked whether it was provided. It is now only required when ``state`` is ``present``.
- openssl_certificate - fix ``assertonly`` provider certificate verification, causing 'private key mismatch' and 'subject mismatch' errors.
- openssl_certificate and openssl_csr - fix Ed25519 and Ed448 private key support for ``cryptography`` backend. This probably needs at least cryptography 2.8, since older versions have problems with signing certificates or CSRs with such keys. (https://github.com/ansible/ansible/issues/59039, PR https://github.com/ansible/ansible/pull/63984)
- openssl_csr - a warning is issued if an unsupported value for ``version`` is used for the ``cryptography`` backend.
- openssl_csr - the module will now enforce that ``privatekey_path`` is specified when ``state=present``.
- openssl_publickey - fix a module crash caused when pyOpenSSL is not installed (https://github.com/ansible/ansible/issues/67035).

New Modules
-----------

- community.crypto.ecs_domain - Request validation of a domain with the Entrust Certificate Services (ECS) API
- community.crypto.x509_crl - Generate Certificate Revocation Lists (CRLs)
- community.crypto.x509_crl_info - Retrieve information on Certificate Revocation Lists (CRLs)

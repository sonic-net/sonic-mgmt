# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.9] - 2025-11-10

### Security
- Updated Ubuntu base image in dev/test_app_ubuntu to latest and nginx base image in dev/Dockerfile_nginx to 1.28.0-alpine-slim (CNJR-11776)

### Added
- Added `close-stale.yml` GitHub workflow

## [1.3.8] - 2025-09-30

### Changed
- Updated documentation to align with Conjur Enterprise name change to Secrets Manager. (CNJR-10991)

## [1.3.7] - 2025-08-13

### Fixed
- Fixed an issue in variable lookup plugin where TLS verification fails even when 
  the Conjur certificate was issued by a trusted CA. (CNJR-7650)

### Changed
- Raised minimum required Ansible version to 2.17.

## [1.3.6] - 2025-06-11

### Added
- Added support for AWS, Azure, and GCP authentication

## [1.3.5] - 2025-03-28

### Added
- Added Telemetry Headers

## [1.3.4] - 2025-03-26

### Added
- Added Codacy integration

## [1.3.3] - 2025-02-26

### Fixed
- Fixed various code quality issues (CNJR-6414)

## [1.3.2] - 2024-12-12

### Added
- Added ignore file for ansible-core 2.18 sanity test
- The Lookup plugin now supports certificate content as a parameter variable

## [1.3.1] - 2024-10-16

### Added
- Automated cloud tests

## [1.3.0] - 2024-05-23

### Added
- Lookup plugin supports configuration by Ansible variables
  [cyberark/ansible-conjur-collection#203](https://github.com/cyberark/ansible-conjur-collection/pull/203)

## [1.2.2] - 2023-09-28

### Changed
- Bump required Ansible version to >= 2.13
  [cyberark/ansible-conjur-collection#198](https://github.com/cyberark/ansible-conjur-collection/pull/198)
- Ignore dev folder when building the collection
  [cyberark/ansible-conjur-collection#198](https://github.com/cyberark/ansible-conjur-collection/pull/198)

## [1.2.1] - 2023-09-20

### Fixed
- Restore custom error messages for missing required variables.
  [cyberark/ansible-conjur-collection#197](https://github.com/cyberark/ansible-conjur-collection/pull/197)

### Added
- Tests against Ansible versions 6, 7 and 8.
  [cyberark/ansible-conjur-collection#195](https://github.com/cyberark/ansible-conjur-collection/pull/195)

### Security
- Upgrade dev/test nginx base images to 1.24.0, ubuntu base image to 22.04.
  [cyberark/ansible-conjur-collection#189](https://github.com/cyberark/ansible-conjur-collection/pull/189)
- Clean up unused Python imports.
  [cyberark/ansible-conjur-collection#194](https://github.com/cyberark/ansible-conjur-collection/pull/194)

## [1.2.0] - 2020-09-01

### Added
- Add `state` variable to Conjur Ansible role, which can be used to cleanup
  configuration and identity artifacts created on managed nodes.
  [cyberark/ansible-conjur-collection#176](https://github.com/cyberark/ansible-conjur-collection/pull/176)

### Changed
- Lookup plugin now retries variable retrieval 5 times before accepting a
  failure response.
  [cyberark/ansible-conjur-collection#60](https://github.com/cyberark/ansible-conjur-collection/pull/60)

### Removed
- End support for Python 2.
  [cyberark/ansible-conjur-collection#69](https://github.com/cyberark/ansible-conjur-collection/pull/69)

## [1.1.0] - 2020-12-29

### Added
- The [Conjur Ansible role](https://galaxy.ansible.com/cyberark/conjur-host-identity) has been
  migrated to this collection, where it will be maintained moving forward.
  At current, the role in the collection is aligned with the v0.3.2 release of
  the standalone role.
  [cyberark/ansible-conjur-host-identity#30](https://github.com/cyberark/ansible-conjur-host-identity/issues/30)
- Add `as_file` boolean option to the lookup plugin which stores the secret as
  a temporary file and returns its path. This enables users to use the
  `ansible_ssh_private_key_file` parameter to define an SSH private key using a
  variable stored in Conjur; previously, users couldn't set this parameter via
  a direct call to the lookup plugin because the parameter does not accept
  inline SSH keys, and the lookup plugin could only return a string.
  [cyberark/ansible-conjur-collection#52](https://github.com/cyberark/ansible-conjur-collection/issues/52),
  [Cyberark Commons post #1070](https://discuss.cyberarkcommons.org/t/conjur-ansible-lookup-plugin-and-ssh-key-file/1070) 

## [1.0.7] - 2020-08-20

### Changed
- Various improvements to code quality, documentation, and adherence to Ansible standards
  in preparation for including this collection in the release of Ansible 2.10.
  [cyberark/ansible-conjur-collection#30](https://github.com/cyberark/ansible-conjur-collection/issues/30)

## [1.0.6] - 2020-07-01

### Added
- Plugin supports authenticating with Conjur access token (for example, if provided by authn-k8s).
  [cyberark/ansible-conjur-collection#23](https://github.com/cyberark/ansible-conjur-collection/issues/23)

## [1.0.5] - 2020-06-18

### Added
- Plugin supports validation of self-signed certificates provided in `CONJUR_CERT_FILE`
  or Conjur config file
  ([cyberark/ansible-conjur-collection#4](https://github.com/cyberark/ansible-conjur-collection/issues/4))

### Fixed
- Encode spaces to "%20" instead of "+". This encoding fixes an issue where Conjur
  variables that have spaces were not encoded correctly 
  ([cyberark/ansible-conjur-collection#12](https://github.com/cyberark/ansible-conjur-collection/issues/12))
- Allow users to set `validate_certs` to `false` without setting a value to `cert_file`
  ([cyberark/ansible-conjur-collection#13](https://github.com/cyberark/ansible-conjur-collection/issues/13))

## [1.0.3] - 2020-04-18
### Changed
- Updated documentation section to comply with sanity checks

## [1.0.2] - 2020-04-01
### Added
- Migrated code from Ansible conjur_variable lookup plugin
- Added support to configure the use of the plugin via environment variables

[Unreleased]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.3.9...HEAD
[1.3.9]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.3.8...v1.3.9
[1.3.8]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.3.7...v1.3.8
[1.3.7]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.3.6...v1.3.7
[1.3.6]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.3.3...v1.3.6
[1.3.3]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.0.7...v1.1.0
[1.0.7]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.0.3...v1.0.5
[1.0.3]: https://github.com/cyberark/ansible-conjur-collection/compare/v1.0.2...v1.0.3

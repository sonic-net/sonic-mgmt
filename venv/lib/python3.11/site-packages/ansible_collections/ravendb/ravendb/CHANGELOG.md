# Changelog

All notable changes to this project will be documented in this file.

This project follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) principles.

The full changelog is maintained in [changelogs/changelog.yml](./changelogs/changelog.yml).

## [1.0.0] - Initial Release

### Added
- Initial release of the `ravendb.ravendb` Ansible Collection.
- Added `ravendb_node` role for setting up RavenDB servers.
- Added `ravendb_python_client_prerequisites` role for managing Python dependencies.
- Added modules:
  - `ravendb.ravendb.database` for managing RavenDB databases.
  - `ravendb.ravendb.index` for managing RavenDB indexes and index modes.
  - `ravendb.ravendb.node` for adding nodes to a RavenDB cluster.

## [1.0.1] - 2025-07-15

### Fixed
- `galaxy.yml` now points to the collection repo's issue tracker.
- Removed broken external changelog link in `CHANGELOG.md`.
- Added `attributes:` with `check_mode` support to all modules.
- Replaced partial module names in roles/playbooks with full FQCNs.
- Removed leftover files: `ansible.cfg`, `inventories/`, etc.
- CI matrix now includes `stable-2.18`, `stable-2.19`, and Python 2.7 testing.

## [1.0.2] - 2025-07-29

### Changed
- Flattened arguments in the `ravendb.ravendb.node` module for clarity (removed nested `node:` dict).
- Reorganized common module arguments (`url`, `database_name`, `certification_path`, `ca_cert_path`) into `module_utils` and `doc_fragments`.

### Fixed
- Ensured all modules correctly import and expose shared argument definitions.


## [1.0.3] - 2025-08-19

### Added
- Support for encrypted databases in `ravendb.ravendb.database`:
  - Generate or read encryption keys.
  - Distribute keys across all cluster nodes.
  - Create databases with encryption enabled.
- Ability to manage database settings via the `ravendb.ravendb.database` module.
- Joining Let's Encrypt–secured nodes into existing RavenDB clusters.


## [1.0.4] - 2025-09-04

### Added
- Database placement on specific nodes via `topology_members` in `ravendb.ravendb.database`.
- Index deployment mode support (`rolling`, `parallel`) in `ravendb.ravendb.index`.
- Per-index configuration reconciliation via `index_configuration` in `ravendb.ravendb.index`.
- New `ravendb.ravendb.healthcheck` module:
  - Available checks: `node_alive`, `cluster_connectivity`, `db_groups_available`, `db_groups_available_excluding_target`.
  - TLS parameters: `validate_certificate`, `certificate_path`, `ca_cert_path`.
  - Timing/behavior: `max_time_to_wait`, `retry_interval_seconds`, `db_retry_interval_seconds`, `on_db_timeout`.
  - Safety: auto-disables validation for IP hosts on node/cluster checks, read-only (no changes).
- New `ravendb.ravendb.connection_string` module:
  - Providers: `RAVEN`, `SQL`, `OLAP`, `ELASTIC_SEARCH`, `QUEUE` (Kafka, RabbitMQ, AzureQueueStorage, AmazonSQS), `SNOWFLAKE`, `AI`.
  - All secrets parameters are treated as literal strings, If you need to load a secret from disk or the environment, use Ansible lookups.
  - Check mode support for connection strings.
### Changed
- Modularized the project internals for clearer responsibilities and easier maintenance.

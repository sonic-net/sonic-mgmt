# ravendb_python_client_prerequisites

This role sets up a dedicated Python virtual environment under `~/.ravendb_ansible`, installs `python3`, `pip`, `python3-venv`, and ensures the RavenDB Python client and `requests` package are available inside the virtual environment.

## Requirements

- Python 3 must be available on the target machine
- Root/sudo access for package installation

## Role Variables

- `ravendb_venv_path`: Path to the virtual environment (default: `~/.ravendb_ansible`)

## Example Playbook

```yaml
- hosts: all
  roles:
    - role: ravendb_python_client_prerequisites

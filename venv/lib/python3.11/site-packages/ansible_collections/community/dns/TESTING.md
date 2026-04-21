<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Running tests

## Prerequisites

For testing, you need to check out the collection repository in a specific path structure: the checkout needs to be in `ansible_collections/community/dns`. This is both a requirement of `ansible-test` and for the current implementation of `pylint` and `mypy` code checks.

You also need the collection's dependency, `community.library_inventory_filtering_v1`, installed in the same tree structure, i.e. in `ansible_collections/community/library_inventory_filtering_v1`. Note that the repository (https://github.com/ansible-collections/community.library_inventory_filtering/) does not have the `_v1` suffix in its name.

For **unit tests** and the `nox`-based **sanity tests**, you also need `community.internal_test_tools` installed in the same tree, at `ansible_collections/community/internal_test_tools`.

Finally, for the **integration tests**, you also need `community.general` installed in the same tree, at `ansible_collections/community/general`.

## Running ansible-test based sanity tests

To run all sanity tests: `ansible-test sanity --docker -v`

TODO: Use nox for this
`nox -e ansible-test-sanity-devel`

## Running nox based sanity tests and code formatting

These tests require [`nox` (version 2025.02.09 or greater)](https://pypi.org/project/nox) and [`antsibull-nox`](https://pypi.org/project/antsibull-nox/). Note that running `nox` without `antsibull-nox` present will automatically create a venv that installs all needed requirements. You can also use `pipx run noxfile.py` or similar Python runners; they detect the script metadata in `noxfile.py` and will automatically install `nox` and `antsibull-nox`. Details can be found [on the antsibull-nox Getting Started page](https://docs.ansible.com/projects/antsibull-nox/getting-started/#running-tests).

Run `nox -e lint` to run all sanity tests, including code formatting.

You can also run more specific sessions directly:
* `nox -e formatters` to run the code formatters (black; currently restricted to Python 3+ code);
* `nox -e codeqa` to run code QA linters (flake8 and pylint);
* `nox -e typing` to run type checking for Python 3+ code (mypy).

You can use `-Re` instead of `-e` to re-run tests; that will re-use the created virtual environments and avoid re-installation of the requirements. From time to time you should use `-e` again to make sure you have an updated virtual environment. For example, if you notice a discrepancy between CI and running tests locally, using `-e` might be a good idea.

## Running unit tests

To run all unit tests for all supported (by your ansible-core version) Python versions, run `ansible-test units --docker -v`.

To run all unit tests for a specific Python version (this is usually sufficient and much faster): `ansible-test units --docker -v --python 3.13`

TODO: Use nox for this
`nox -e ansible-test-units-devel`

## HostTech DNS modules

The CI (based on GitHub Actions) does not run integration tests for the HostTech modules, because they need access to HostTech API credentials. If you have some, copy [`tests/integration/integration_config.yml.hosttech-template`](https://github.com/ansible-collections/community.dns/blob/main/tests/integration/integration_config.yml.hosttech-template) to `integration_config.yml` in the same directory, and insert username, key, a test zone (`domain.ch`) and test record (`foo.domain.ch`). Then run `ansible-test integration --allow-unsupported hosttech`. Please note that the test record will be deleted, (re-)created, and finally deleted, so do not use any record you actually need!

To run the tests with Python 3.13:
```
ansible-test integration --docker default --python 3.13 --allow-unsupported hosttech
```
You can adjust the Python version, remove `--python 3.13` completely, use a different docker container, or remove `--docker default` completely.

## Hetzner DNS modules

The CI (based on GitHub Actions) does not run integration tests for the Hetzner modules, because they need access to Hetzner API credentials. If you have some, copy [`tests/integration/integration_config.yml.hetzner-template`](https://github.com/ansible-collections/community.dns/blob/main/tests/integration/integration_config.yml.hetzner-template) to `integration_config.yml` in the same directory, and insert API key and a test zone (`domain.de`). Then run `ansible-test integration --allow-unsupported hetzner`. Please note that the test zone will be modified, so do not use a zone you actually need!

To run the tests with Python 3.13:
```
ansible-test integration --docker default --python 3.13 --allow-unsupported hetzner
```
You can adjust the Python version, remove `--python 3.13` completely, use a different docker container, or remove `--docker default` completely.

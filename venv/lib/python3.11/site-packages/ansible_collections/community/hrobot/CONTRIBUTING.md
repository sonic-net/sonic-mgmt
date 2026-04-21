<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Contributing

We follow [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html) in all our contributions and interactions within this repository.

## Test pull requests

If you want to test a PR locally, refer to [our testing guide](https://github.com/ansible/community-docs/blob/main/test_pr_locally_guide.rst) for instructions on how do it quickly.

If you find any inconsistencies or places in this document which can be improved, feel free to raise an issue or pull request to fix it.

## Run sanity or unit locally (with antsibull-nox)

The easiest way to run sanity and unit tests locally is to use [antsibull-nox](https://ansible.readthedocs.io/projects/antsibull-nox/).
(If you have [nox](https://nox.thea.codes/en/stable/) installed, it will automatically install antsibull-nox in a virtual environment for you.)

### Sanity tests

The following commands show how to run ansible-test sanity tests:

```.bash
# Run basic sanity tests for all files in the collection:
nox -Re ansible-test-sanity-devel

# Run basic sanity tests for the given files and directories:
nox -Re ansible-test-sanity-devel -- plugins/modules/boot.py tests/unit/plugins/module_utils/

# Run all other sanity tests for all files in the collection:
nox -R
```

If you replace `-Re` with `-e`, respectively.
If you leave `-R` away, then the virtual environments will be re-created.
The `-R` re-uses them (if they already exist).

### Unit tests

The following commands show how to run unit tests:

```.bash
# Run all unit tests:
nox -Re ansible-test-units-devel

# Run all unit tests for one Python version (a lot faster):
nox -Re ansible-test-units-devel -- --python 3.13

# Run a specific unit test (for the community.hrobot.boot module) for one Python version:
nox -Re ansible-test-units-devel -- --python 3.13 tests/unit/plugins/modules/test_boot.py
```

If you replace `-Re` with `-e`, then the virtual environments will be re-created.
The `-R` re-uses them (if they already exist).

## Run basic sanity, unit or integration tests locally (with ansible-test)

Instead of using antsibull-nox,
you can also run sanity and unit tests with ansible-test directly.

You have to check out the repository into a specific path structure to be able to run `ansible-test`.
The path to the git checkout must end with `.../ansible_collections/community/hrobot`.
Please see [our testing guide](https://github.com/ansible/community-docs/blob/main/test_pr_locally_guide.rst) for instructions on how to check out the repository into a correct path structure.
The short version of these instructions is:

```.bash
mkdir -p ~/dev/ansible_collections/community
git clone https://github.com/ansible-collections/community.hrobot.git ~/dev/ansible_collections/community/hrobot
cd ~/dev/ansible_collections/community/hrobot
```

Then you can run `ansible-test` (which is a part of [ansible-core](https://pypi.org/project/ansible-core/)) inside the checkout.
The following example commands expect that you have installed Docker or Podman.

### Basic sanity tests

The following commands show how to run basic sanity tests:

```.bash
# Run basic sanity tests for all files in the collection:
ansible-test sanity --docker -v

# Run basic sanity tests for the given files and directories:
ansible-test sanity --docker -v plugins/modules/boot.py tests/unit/plugins/module_utils/
```

### Unit tests

Note that for running unit tests,
you need to install required collections in the same folder structure that `community.hrobot` is checked out in.
Right now, you need to install [`community.internal_test_tools`](https://github.com/ansible-collections/community.internal_test_tools).
If you want to use the latest version from GitHub,
you can run:
```
git clone https://github.com/ansible-collections/community.internal_test_tools.git ~/dev/ansible_collections/community/internal_test_tools
```

The following commands show how to run unit tests:

```.bash
# Run all unit tests:
ansible-test units --docker -v

# Run all unit tests for one Python version (a lot faster):
ansible-test units --docker -v --python 3.8

# Run a specific unit test (for the community.hrobot.boot module) for one Python version:
ansible-test units --docker -v --python 3.8 tests/unit/plugins/modules/test_boot.py
```

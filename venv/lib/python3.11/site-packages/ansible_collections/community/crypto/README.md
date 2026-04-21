<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Ansible Community Crypto Collection

[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/ansible/devel/collections/community/crypto/)
[![Build Status](https://dev.azure.com/ansible/community.crypto/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ansible/community.crypto/_build?definitionId=21)
[![Nox CI](https://github.com/ansible-collections/community.crypto/actions/workflows/nox.yml/badge.svg?branch=main)](https://github.com/ansible-collections/community.crypto/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.crypto)](https://codecov.io/gh/ansible-collections/community.crypto)
[![REUSE status](https://api.reuse.software/badge/github.com/ansible-collections/community.crypto)](https://api.reuse.software/info/github.com/ansible-collections/community.crypto)

Provides modules for [Ansible](https://www.ansible.com/community) for various cryptographic operations.

You can find [documentation for this collection on the Ansible docs site](https://docs.ansible.com/ansible/latest/collections/community/crypto/).

Please note that this collection does **not** support Windows targets.

## Code of Conduct

We follow [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior violating the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html), please refer to the [policy violations](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html#policy-violations) section of the Code of Conduct for information on how to raise a complaint.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please add appropriate tags if you start new discussions, for example the `crypto` or `acme` tags.
  * [Posts tagged with 'crypto'](https://forum.ansible.com/tag/crypto): subscribe to participate in cryptography related conversations.
  * [Posts tagged with 'acme'](https://forum.ansible.com/tag/acme): subscribe to participate in ACME (RFC 8555) related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Tested with Ansible

Tested with the current ansible-core-2.17, ansible-core 2.18, and ansible-core 2.19 releases and the current development version of ansible-core. Ansible-core versions before 2.17 are not supported; please use community.crypto 2.x.y with these.

## External requirements

The exact requirements for every module are listed in the module documentation.

Most modules require a recent enough version of [the Python cryptography library](https://pypi.org/project/cryptography/); the minimum supported version by this collection is 3.3. See the module documentations for the minimal version supported for each module.

## Collection Documentation

Browsing the [**latest** collection documentation](https://docs.ansible.com/ansible/latest/collections/community/crypto) will show docs for the _latest version released in the Ansible package_, not the latest version of the collection released on Galaxy.

Browsing the [**devel** collection documentation](https://docs.ansible.com/ansible/devel/collections/community/crypto) shows docs for the _latest version released on Galaxy_.

We also separately publish [**latest commit** collection documentation](https://ansible-collections.github.io/community.crypto/branch/main/) which shows docs for the _latest commit in the `main` branch_.

If you use the Ansible package and do not update collections independently, use **latest**. If you install or update this collection directly from Galaxy, use **devel**. If you are looking to contribute, use **latest commit**.

## Using this collection

Before using the crypto community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install community.crypto

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: community.crypto
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

<!--Describe how the community can contribute to your collection. At a minimum, include how and where users can create issues to report problems or request features for this collection.  List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. If you are following general Ansible contributor guidelines, you can link to - [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html). -->

We're following the general Ansible contributor guidelines; see [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).

If you want to clone this repositority (or a fork of it) to improve it, you can proceed as follows:
1. Create a directory `ansible_collections/community`;
2. In there, checkout this repository (or a fork) as `crypto`;
3. Add the directory containing `ansible_collections` to your [ANSIBLE_COLLECTIONS_PATH](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths).

See [Ansible's dev guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections) for more information.

## Release notes

See the [changelog](https://github.com/ansible-collections/community.crypto/blob/main/CHANGELOG.md).

## Roadmap

We plan to regularly release minor and patch versions, whenever new features are added or bugs fixed. Our collection follows [semantic versioning](https://semver.org/), so breaking changes will only happen in major releases.

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

This collection is primarily licensed and distributed as a whole under the GNU General Public License v3.0 or later.

See [LICENSES/GPL-3.0-or-later.txt](https://github.com/ansible-collections/community.crypto/blob/main/COPYING) for the full text.

Parts of the collection are licensed under the [Apache 2.0 license](https://github.com/ansible-collections/community.crypto/blob/main/LICENSES/Apache-2.0.txt) (`plugins/module_utils/_crypto/_obj2txt.py` and `plugins/module_utils/_crypto/_objects_data.py`) and the [BSD 3-Clause license](https://github.com/ansible-collections/community.crypto/blob/main/LICENSES/BSD-3-Clause.txt) (`plugins/module_utils/_crypto/_obj2txt.py`). This only applies to vendored files in ``plugins/module_utils/``.

All files have a machine readable `SDPX-License-Identifier:` comment denoting its respective license(s) or an equivalent entry in an accompanying `.license` file. Only changelog fragments (which will not be part of a release) are covered by a blanket statement in `REUSE.toml`. This conforms to the [REUSE specification](https://reuse.software/spec/).

<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Community DNS Collection
[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/projects/ansible/devel/collections/community/dns/)
[![CI](https://github.com/ansible-collections/community.dns/actions/workflows/nox.yml/badge.svg?branch=main)](https://github.com/ansible-collections/community.dns/actions)
[![Public Suffix List up-to-date](https://github.com/ansible-collections/community.dns/actions/workflows/check-psl.yml/badge.svg?branch=main)](https://github.com/ansible-collections/community.dns/actions/workflows/check-psl.yml)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.dns)](https://codecov.io/gh/ansible-collections/community.dns)
[![REUSE status](https://api.reuse.software/badge/github.com/ansible-collections/community.dns)](https://api.reuse.software/info/github.com/ansible-collections/community.dns)

This repository contains the `community.dns` Ansible Collection. The collection includes plugins and modules to work with DNS.

Please note that this collection does **not** support Windows targets.

## Code of Conduct

We follow [Ansible Code of Conduct](https://docs.ansible.com/projects/ansible/latest/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior violating the [Ansible Code of Conduct](https://docs.ansible.com/projects/ansible/latest/community/code_of_conduct.html), please refer to the [policy violations](https://docs.ansible.com/projects/ansible/latest/community/code_of_conduct.html#policy-violations) section of the Code of Conduct for information on how to raise a complaint.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please add appropriate tags if you start new discussions, for example the `dns` tag.
  * [Posts tagged with 'dns'](https://forum.ansible.com/tag/dns): subscribe to participate in DNS related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/projects/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/projects/ansible/devel/community/communication.html).

## Tested with Ansible

Tested with the current ansible-core 2.14, ansible-core 2.15, ansible-core 2.16, ansible-core 2.17, ansible-core 2.18, and ansible-core 2.19 releases and the current development version of ansible-core. Ansible versions before 2.9.10 are not supported.

## External requirements

Depends on the plugin or module used.

## Collection Documentation

Browsing the [**latest** collection documentation](https://docs.ansible.com/projects/ansible/latest/collections/community/dns/) will show docs for the _latest version released in the Ansible package_, not the latest version of the collection released on Galaxy.

Browsing the [**devel** collection documentation](https://docs.ansible.com/projects/ansible/devel/collections/community/dns/) shows docs for the _latest version released on Galaxy_.

We also separately publish [**latest commit** collection documentation](https://ansible-collections.github.io/community.dns/branch/main/) which shows docs for the _latest commit in the `main` branch_.

If you use the Ansible package and do not update collections independently, use **latest**. If you install or update this collection directly from Galaxy, use **devel**. If you are looking to contribute, use **latest commit**.

## Included content

- Modules:
  - `hetzner_dns_record_info`: retrieve information on DNS records from Hetzner DNS.
  - `hetzner_dns_record`: create/update/delete single DNS records with Hetzner DNS.
  - `hetzner_dns_record_set_info`: retrieve information on DNS record sets from Hetzner DNS.
  - `hetzner_dns_record_set`: create/update/delete DNS record sets with Hetzner DNS.
  - `hetzner_dns_record_sets`: bulk synchronize DNS record sets in Hetzner DNS service.
  - `hetzner_dns_zone_info`: retrieve zone information from Hetzner DNS.
  - `hosttech_dns_record_info`: retrieve information on DNS records from HostTech DNS.
  - `hosttech_dns_record`: create/update/delete single DNS records with HostTech DNS.
  - `hosttech_dns_record_set_info`: retrieve information on DNS record sets from HostTech DNS.
  - `hosttech_dns_record_set`: create/update/delete DNS record sets with HostTech DNS.
  - `hosttech_dns_record_set`: bulk synchronize DNS record sets in Hosttech DNS service.
  - `hosttech_dns_zone_info`: retrieve zone information from HostTech DNS.
  - `nameserver_info`: Look up nameservers for a DNS name.
  - `nameserver_record_info`: Look up all records of a type from all nameservers for a DNS name.
  - `wait_for_txt`: wait for TXT records to propagate to all name servers.
- Lookup plugins:
  - `lookup`: look up DNS records and return them as a list of strings.
  - `lookup_as_dict`: look up DNS records and return them as a list of dictionaries.
  - `reverse_lookup`: reverse-look up IP addresses.
- Inventory plugins:
  - `hetzner_dns_records`: create inventory from Hetzner DNS records.
  - `hosttech_dns_records`: create inventory from HostTech DNS records.
- Filters:
  - `get_public_suffix`: given a domain name, returns the public suffix. For example, `"www.ansible.com" | community.dns.get_public_suffix == ".com"` and `"some.random.prefixes.ansible.co.uk" | community.dns.get_public_suffix == ".co.uk"`.
  - `get_registrable_domain`: given a domain name, returns the *registrable domain name* (also called *registered domain name*). For example, `"www.ansible.com" | community.dns.get_registrable_domain == "ansible.com"` and `"some.random.prefixes.ansible.co.uk" | community.dns.get_registrable_domain == "ansible.co.uk"`.
  - `remove_public_suffix`: given a domain name, returns the part before the public suffix. For example, `"www.ansible.com" | community.dns.remove_public_suffix == "www.ansible"` and `"some.random.prefixes.ansible.co.uk" | community.dns.remove_public_suffix == "some.random.prefixes.ansible"`.
  - `remove_registrable_domain`: given a domain name, returns the part before the DNS zone. For example, `"www.ansible.com" | community.dns.remove_registrable_domain == "www"` and `"some.random.prefixes.ansible.co.uk" | community.dns.remove_registrable_domain == "some.random.prefixes"`.
  - `reverse_pointer`: convert an IP address into a DNS name for reverse lookup.
  - `quote_txt`: quotes a string for use as a TXT record entry. For example, `"this is a test" | community.dns.quote_txt == '"this is a test"'`.
  - `unquote_txt`: unquotes a TXT record entry. For example, `'"foo" "bar"' | community.dns.unquote_txt == "foobar"`.

## Using this collection

Before using the General community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install community.dns

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: community.dns
```

See [Ansible Using collections](https://docs.ansible.com/projects/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

If you want to develop new content for this collection or improve what is already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATH`](https://docs.ansible.com/projects/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

See [TESTING.md](https://github.com/ansible-collections/community.dns/tree/main/TESTING.md) for information on running the tests.

You can find more information in the [developer guide for collections](https://docs.ansible.com/projects/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections), and in the [Ansible Community Guide](https://docs.ansible.com/projects/ansible/latest/community/index.html).

## Release notes

See the [changelog](https://github.com/ansible-collections/community.dns/tree/main/CHANGELOG.md).

## Releasing, Versioning and Deprecation

This collection follows [Semantic Versioning](https://semver.org/). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_collections.html#collection-versions).

We plan to regularly release new minor or bugfix versions once new features or bugfixes have been implemented.

Releasing the current major version happens from the `main` branch. We will create a `stable-1` branch for 1.x.y versions once we start working on a 2.0.0 release, to allow backporting bugfixes and features from the 2.0.0 branch (`main`) to `stable-1`. A `stable-2` branch will be created once we work on a 3.0.0 release, and so on.

We currently are not planning any deprecations or new major releases like 2.0.0 containing backwards incompatible changes. If backwards incompatible changes are needed, we plan to deprecate the old behavior as early as possible. We also plan to backport at least bugfixes for the old major version for some time after releasing a new major version. We will not block community members from backporting other bugfixes and features from the latest stable version to older release branches, under the condition that these backports are of reasonable quality.

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/projects/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/projects/ansible/latest/dev_guide/index.html)
- [Antsibull-nox documentation](https://docs.ansible.com/projects/antsibull-nox/)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/master/collection_requirements.rst)
- [Ansible Community code of conduct](https://docs.ansible.com/projects/ansible/latest/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [Changes impacting Contributors](https://github.com/ansible-collections/overview/issues/45)

## Licensing

This collection is primarily licensed and distributed as a whole under the GNU General Public License v3.0 or later.

See [LICENSES/GPL-3.0-or-later.txt](https://github.com/ansible-collections/community.dns/blob/main/COPYING) for the full text.

The only content of this collection that is not GPL v3.0+ licensed are:
* `plugins/public_suffix_list.dat`, which is subject to the terms of the Mozilla Public License, v. 2.0. See [LICENSES/MPL-2.0.txt](https://github.com/ansible-collections/community.dns/blob/main/LICENSES/MPL-2.0.txt) for the full text.
* `plugins/module_utils/_six.py`, which is licensed under the [MIT license](https://github.com/ansible-collections/community.dns/blob/main/LICENSES/MIT.txt).

All files have a machine readable `SDPX-License-Identifier:` comment denoting its respective license(s) or an equivalent entry in an accompanying `.license` file. Only changelog fragments (which will not be part of a release) are covered by a blanket statement in `REUSE.toml`. This conforms to the [REUSE specification](https://reuse.software/spec/).

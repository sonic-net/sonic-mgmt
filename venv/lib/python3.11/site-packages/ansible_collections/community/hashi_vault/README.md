# community.hashi_vault Collection
<!-- Add CI and code coverage badges here. Samples included below. -->
[![CI](https://github.com/ansible-collections/community.hashi_vault/workflows/CI/badge.svg?event=push)](https://github.com/ansible-collections/community.hashi_vault/actions) [![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.hashi_vault)](https://codecov.io/gh/ansible-collections/community.hashi_vault)

<!-- Describe the collection and why a user would want to use it. What does the collection do? -->

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please add appropriate tags if you start new discussions, for example the `hashi-vault` tag.
  * [Posts tagged with 'hashi-vault'](https://forum.ansible.com/tag/hashi-vault): subscribe to participate in the technology related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Collection Documentation

Browsing the [**latest** collection documentation](https://docs.ansible.com/ansible/latest/collections/community/hashi_vault) will show docs for the _latest version released in the Ansible package_ not the latest version of the collection released on Galaxy.

Browsing the [**devel** collection documentation](https://docs.ansible.com/ansible/devel/collections/community/hashi_vault) shows docs for the _latest version released on Galaxy_.

We also separately publish [**latest commit** collection documentation](https://ansible-collections.github.io/community.hashi_vault/branch/main/) which shows docs for the _latest commit in the `main` branch_.

If you use the Ansible package and don't update collections independently, use **latest**, if you install or update this collection directly from Galaxy, use **devel**. If you are looking to contribute, use **latest commit**.

## Tested with Ansible

Please refer to the [`ansible-core` support matrix](https://docs.ansible.com/ansible/devel/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix) to see which versions of `ansible-core` are still supported or end-of-life.

Generally, we release a new major version of this collection a little before the release of a new `ansible-core` version, which is around every 6 months. In that release, we will update the CI matrix to drop the core versions that are about to go EoL, and add in new core versions if they have not been added already.

We also regularly test against the [`devel` branch](https://github.com/ansible/ansible/tree/devel) (latest development commit).

See [the CI configuration](https://github.com/ansible-collections/community.hashi_vault/blob/main/.github/workflows/ansible-test.yml) for the most accurate testing information.

## Tested with Vault

We currently test against the latest patch version within the latest two minor versions of the latest major version of Vault. Put another way, we test against version `Z.{Z|Y}.Z`. For example as of this writing, Vault is on major version `1`, with the latest two minors being `8` and `7`. So we'll test Vault `1.8.Z` and `1.7.Z` where `Z` is the latest patch within those versions.

We do not test against any versions of Vault with major version `0` or against pre-release/release candidate (RC) versions.

If/when a new major version of Vault is released, we'll revisit which and how many versions to test against.

The decision of which version(s) of Vault to test against is still somewhat in flux, as we try to balance wide testing with CI execution time and resources.

See [the CI configuration](https://github.com/ansible-collections/community.hashi_vault/blob/main/.github/workflows/ansible-test.yml) for the most accurate testing information.

## Python Requirements

**Python 2.6, 2.7, and 3.5 are not supported in version `2.0.0` or later of the collection.**

Currently we support and test against Python versions:
* 3.8
* 3.9
* 3.10
* 3.11
* 3.12
* 3.13

Note that for controller-side plugins, only the Python versions supported by the Ansible controller are supported (for example, you cannot use Python 3.7 with Ansible core 2.12).

## External requirements

The `hvac` Python library is required for this collection. [For full requirements and details, see the collection's User Guide](https://docs.ansible.com/ansible/devel/collections/community/hashi_vault/docsite/user_guide.html#requirements).

## Included content

[See the list of included content in the docsite](https://docs.ansible.com/ansible/devel/collections/community/hashi_vault/#plugin-index).

## Using this collection

<!--Include some quick examples that cover the most common use cases for your collection content. -->

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

See the contributor guide in the [**devel** collection documentation](https://docs.ansible.com/ansible/devel/collections/community/hashi_vault).

<!--Describe how the community can contribute to your collection. At a minimum, include how and where users can create issues to report problems or request features for this collection.  List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. If you are following general Ansible contributor guidelines, you can link to - [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html). -->

## Releasing this collection (for maintainers)
[Follow the instructions for releasing small collections in the Ansible community wiki](https://github.com/ansible/community/wiki/ReleasingCollections#releasing-without-release-branches-for-smaller-collections).

Once the new collection is published and the Zuul job is finished, add a release in GitHub by [manually running the `GitHub Release` workflow](https://github.com/ansible-collections/community.hashi_vault/actions/workflows/github-release.yml). You'll need to enter the version number, which should exactly match the tag used to release the collection.

## Release notes

See the [rendered changelog](https://ansible-collections.github.io/community.hashi_vault/branch/main/collections/community/hashi_vault/docsite/CHANGELOG.html) or the [raw generated changelog](https://github.com/ansible-collections/community.hashi_vault/tree/main/CHANGELOG.rst).

## FAQ

### **Q:** Why not have a single collection of HashiCorp products instead of one just for Vault?

**A:** This was considered when the `hashi_vault` plugin was first moved from `community.general` to this collection. There are several reasons behind this:

* The other known HashiCorp content at that time (covering Consul, Nomad, Terraform, etc.) does not share implementation or testing with Vault content.
* The maintainers are also different. This being a community supported collection means separate maintainers are more likely to focus on goals that make sense for their particular plugins and user base.
* The HashiCorp products serve different goals, and even when used together, they have their own APIs and interfaces that don't really have anything in common from the point of view of the Ansible codebase as a consumer.
* It would complicate testing. One of the primary goals of moving to a new collection was the ability to increase the scope of Vault-focused testing without having to balance the impact to unrelated components.
* It makes for a smaller package for consumers, that can hopefully release more quickly.

### **Q:** Why is the collection named `community.hashi_vault` instead of `community.vault` or `community.hashicorp_vault` or `hashicorp.vault` or any number of other names?

**A:** This too was considered during formation. In the end, `hashi_vault` is a compromise of various concerns.

* `hashicorp.vault` looks great, but implies the collection is supported by HashiCorp (which it is not). That doesn't follow the convention of denoting community supported namespaces with `community.`
* `community.vault` looks great at first, but "Vault" is a very general and overloaded term, and in Ansible the first "Vault" one thinks of is [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html). So in the naming, and even in the future of this collection and its content, we have to be mindful of avoiding and removing ambiguities between these products (and other Vaults out there).
* `community.hashicorp_vault` is descriptive and unambiguous but is unfortunately quite long.
* `community.hashicorp` would be good for a collection that aims to contain community-supported content related to all HashiCorp products, but this collection is only focused on Vault (see above question).
* `community.hashicorp.vault` (or any other 3-component name): not supported (also long).
* `community.hashi_vault` isn't perfect, but has an established convention in the existing plugin name and isn't as long as `hashicorp_vault`.


## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

<!-- List out where the user can find additional information, such as working group meeting times, slack/IRC channels, or documentation for the product this collection automates. At a minimum, link to: -->

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/master/collection_requirements.rst)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [Changes impacting Contributors](https://github.com/ansible-collections/overview/issues/45)

## Licensing

<!-- Include the appropriate license information here and a pointer to the full licensing details. If the collection contains modules migrated from the ansible/ansible repo, you must use the same license that existed in the ansible/ansible repo. See the GNU license example below. -->

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

Parts of the collection are licensed under the [BSD-2-Clause](https://opensource.org/licenses/BSD-2-Clause) license.

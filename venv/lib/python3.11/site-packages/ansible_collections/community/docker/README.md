<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Docker Community Collection

[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/ansible/devel/collections/community/docker/)
[![Build Status](https://dev.azure.com/ansible/community.docker/_apis/build/status/CI?branchName=stable-4)](https://dev.azure.com/ansible/community.docker/_build?definitionId=25)
[![Nox CI](https://github.com/ansible-collections/community.docker/actions/workflows/nox.yml/badge.svg?branch=stable-4)](https://github.com/ansible-collections/community.docker/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.docker)](https://codecov.io/gh/ansible-collections/community.docker)
[![REUSE status](https://api.reuse.software/badge/github.com/ansible-collections/community.docker)](https://api.reuse.software/info/github.com/ansible-collections/community.docker)

This repo contains the `community.docker` Ansible Collection. The collection includes many modules and plugins to work with Docker.

Please note that this collection does **not** support Windows targets. The connection plugins included in this collection support Windows targets on a best-effort basis, but we are not testing this in CI.

## Code of Conduct

We follow [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior violating the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html), please refer to the [policy violations](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html#policy-violations) section of the Code of Conduct for information on how to raise a complaint.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please add appropriate tags if you start new discussions, for example the `docker`, `docker-compose`, or `docker-swarm` tags.
  * [Posts tagged with 'docker'](https://forum.ansible.com/tag/docker): subscribe to participate in Docker related conversations.
  * [Posts tagged with 'docker-compose'](https://forum.ansible.com/tag/docker-compose): subscribe to participate in Docker Compose related conversations.
  * [Posts tagged with 'docker-swarm'](https://forum.ansible.com/tag/docker-swarm): subscribe to participate in Docker Swarm related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Tested with Ansible

Tested with the current ansible-core 2.15, ansible-core 2.16, ansible-core 2.17, ansible-core 2.18, ansible-core 2.19, and ansible-core 2.20 releases. Ansible/ansible-base versions before 2.15.0 are not supported.

## External requirements

Some modules and plugins require Docker CLI, or other external, programs. Some require the [Docker SDK for Python](https://pypi.org/project/docker/) and some use [requests](https://pypi.org/project/requests/) to directly communicate with the Docker daemon API. All modules and plugins require Python 2.7 or later. Python 2.6 is no longer supported; use community.docker 2.x.y if you need to use Python 2.6.

Installing the Docker SDK for Python also installs the requirements for the modules and plugins that use `requests`. If you want to directly install the Python libraries instead of the SDK, you need the following ones:

- [requests](https://pypi.org/project/requests/);
- [pywin32](https://pypi.org/project/pywin32/) when using named pipes on Windows with the Windows 32 API;
- [paramiko](https://pypi.org/project/paramiko/) when using SSH to connect to the Docker daemon with `use_ssh_client=false`;
- [pyOpenSSL](https://pypi.org/project/pyOpenSSL/) when using TLS to connect to the Docker daemon;
- [backports.ssl_match_hostname](https://pypi.org/project/backports.ssl_match_hostname/) when using TLS to connect to the Docker daemon on Python 2.

If you have Docker SDK for Python < 2.0.0 installed ([docker-py](https://pypi.org/project/docker-py/)), you can still use it for modules that support it, though we recommend to uninstall it and then install [docker](https://pypi.org/project/docker/), the Docker SDK for Python >= 2.0.0. Note that both libraries cannot be installed at the same time. If you accidentally did install them simultaneously, you have to uninstall *both* before re-installing one of them.

## Collection Documentation

Browsing the [**latest** collection documentation](https://docs.ansible.com/ansible/latest/collections/community/docker) will show docs for the _latest version released in the Ansible package_, not the latest version of the collection released on Galaxy.

Browsing the [**devel** collection documentation](https://docs.ansible.com/ansible/devel/collections/community/docker) shows docs for the _latest version released on Galaxy_.

We also separately publish [**latest commit** collection documentation](https://ansible-collections.github.io/community.docker/branch/stable-4/) which shows docs for the _latest commit in the `stable-4` branch_.

If you use the Ansible package and do not update collections independently, use **latest**. If you install or update this collection directly from Galaxy, use **devel**. If you are looking to contribute, use **latest commit**.

## Included content

* Connection plugins:
  - community.docker.docker: use Docker containers as remotes using the Docker CLI program
  - community.docker.docker_api: use Docker containers as remotes using the Docker API
  - community.docker.nsenter: execute commands on the host running the controller container
* Inventory plugins:
  - community.docker.docker_containers: dynamic inventory plugin for Docker containers
  - community.docker.docker_machine: collect Docker machines as inventory
  - community.docker.docker_swarm: collect Docker Swarm nodes as inventory
* Modules:
  * Docker:
    - community.docker.docker_container: manage Docker containers
    - community.docker.docker_container_copy_into: copy a file into a Docker container
    - community.docker.docker_container_exec: run commands in Docker containers
    - community.docker.docker_container_info: retrieve information on Docker containers
    - community.docker.docker_host_info: retrieve information on the Docker daemon
    - community.docker.docker_image: manage Docker images
    - community.docker.docker_image_build: build Docker images using Docker buildx
    - community.docker.docker_image_export: export (archive) Docker images
    - community.docker.docker_image_info: retrieve information on Docker images
    - community.docker.docker_image_load: load Docker images from archives
    - community.docker.docker_image_pull: pull Docker images from registries
    - community.docker.docker_image_push: push Docker images to registries
    - community.docker.docker_image_remove: remove Docker images
    - community.docker.docker_image_tag: tag Docker images with new names and/or tags
    - community.docker.docker_login: log in and out to/from registries
    - community.docker.docker_network: manage Docker networks
    - community.docker.docker_network_info: retrieve information on Docker networks
    - community.docker.docker_plugin: manage Docker plugins
    - community.docker.docker_prune: prune Docker containers, images, networks, volumes, and build data
    - community.docker.docker_volume: manage Docker volumes
    - community.docker.docker_volume_info: retrieve information on Docker volumes
  * Docker Compose:
    - community.docker.docker_compose_v2: manage Docker Compose files (Docker compose CLI plugin)
    - community.docker.docker_compose_v2_exec: run command in a container of a Compose service
    - community.docker.docker_compose_v2_pull: pull a Docker compose project
    - community.docker.docker_compose_v2_run: run command in a new container of a Compose service
  * Docker Swarm:
    - community.docker.docker_config: manage configurations
    - community.docker.docker_node: manage Docker Swarm nodes
    - community.docker.docker_node_info: retrieve information on Docker Swarm nodes
    - community.docker.docker_secret: manage secrets
    - community.docker.docker_swarm: manage Docker Swarm
    - community.docker.docker_swarm_info: retrieve information on Docker Swarm
    - community.docker.docker_swarm_service: manage Docker Swarm services
    - community.docker.docker_swarm_service_info: retrieve information on Docker Swarm services
  * Docker Stack:
    - community.docker.docker_stack: manage Docker Stacks
    - community.docker.docker_stack_info: retrieve information on Docker Stacks
    - community.docker.docker_stack_task_info: retrieve information on tasks in Docker Stacks
  * Other:
    - current_container_facts: return facts about whether the module runs in a Docker container

## Using this collection

Before using the Docker community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install community.docker

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: community.docker
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

If you want to develop new content for this collection or improve what is already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATH`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

You can find more information in the [developer guide for collections](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections), and in the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).

## Release notes

See the [changelog](https://github.com/ansible-collections/community.docker/tree/stable-4/CHANGELOG.md).

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/master/collection_requirements.rst)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [Changes impacting Contributors](https://github.com/ansible-collections/overview/issues/45)

## Licensing

This collection is primarily licensed and distributed as a whole under the GNU General Public License v3.0 or later.

See [LICENSES/GPL-3.0-or-later.txt](https://github.com/ansible-collections/community.docker/blob/stable-4/COPYING) for the full text.

Parts of the collection are licensed under the [Apache 2.0 license](https://github.com/ansible-collections/community.docker/blob/stable-4/LICENSES/Apache-2.0.txt). This mostly applies to files vendored from the [Docker SDK for Python](https://github.com/docker/docker-py/).
Also `plugins/module_utils/_six.py` is licensed under the [MIT license](https://github.com/ansible-collections/community.dns/blob/stable-4/LICENSES/MIT.txt).

All files have a machine readable `SDPX-License-Identifier:` comment denoting its respective license(s) or an equivalent entry in an accompanying `.license` file. Only changelog fragments (which will not be part of a release) are covered by a blanket statement in `REUSE.toml`. This conforms to the [REUSE specification](https://reuse.software/spec/).

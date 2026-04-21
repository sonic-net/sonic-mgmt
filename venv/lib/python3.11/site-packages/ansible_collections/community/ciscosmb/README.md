# Ansible Cisco Small Bussiness Switches (SMB) module

Thorough project check -
[![CI](https://github.com/ansible-collections/community.ciscosmb/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/ansible-collections/community.ciscosmb/actions/workflows/CI.yml)

Ansible Galaxy module for Cisco SMB switches - SG250, SG300, SG500, SG350, SG550, CBS350, C1300

## Communication

- Join the Ansible forum:

  - [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  - [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  - [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social
    events.

- The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn):
  used to announce releases and important changes.

For more information about communication, see the
[Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Install

```
ansible-galaxy collection install community.ciscosmb
```

## Usage examples

Tested on devices:

- SG250-10P
- SG350-10-K9
- SG350-28-K9
- SG500-52-K9
- SG550X-24MP-K9
- CBS350-24P-4G
- SG550X-48 stack
- C1300

Known to be used with broad range of:

- Cisco 250 Series Smart Switches
- Cisco Business 350 Series Managed Switches
- Cisco 350 Series Stackable Managed Switches
- Cisco 350X Series Stackable Managed Switches
- Cisco 500 Series Stackable Managed Switches
- Cisco 550X Series Stackable Managed Switches
- Cisco Catalyst 1300 Series Switches

### Required device configuration

Access setup

```
! you should set enable password
enable password level 15

! on user you have two choices
! use unpriviledged user (for example priv. 7) and "become mode"
username user1 privilege 7

! or user with full privileges (priv 15)
username user2 privelege 15
```

Cisco's SSH server setup

```
! you have to enable SSH server
ip ssh server
! enable password and/or key
ip ssh password-auth
ip ssh pubkey-auth auto-login
! generate switch ssh key pair if you did not before
crypto key generate rsa

! if you use public keys for users login configure that keys
crypto key pubkey-chain ssh
user-key user2 rsa
key-string AAAAB3NzaC1......XYZ==
exit
```

### Python versions

Tested on Python versions:

- 3.6
- 3.7
- 3.8
- 3.9
- 3.10
- 3.11
- 3.12

### Running examples

For your tests or quick startup use files form repository:
[cismosmb_inventory_template.yml](./ciscosmb_inventory_template.yml),
[cismosmb_gather_facts.yml](./ciscosmb_gather_facts.yml), [cismosmb_commands.yml](./ciscosmb_commands.yml) .

Prepare your inventory file - copy file [cismosmb_inventory_template.yml](./ciscosmb_inventory_template.yml) to
`cismosmb_inventory.yml` and make your changes.

Then you can run

```
ansible-playbook -i ciscosmb_inventory.yml cismosmb_gather_facts.yml
```

or

```
ansible-playbook -i ciscosmb_inventory.yml cismosmb_commands.yml
```

## Developement

### Setup environment

```
git clone https://github.com/ansible-collections/community.ciscosmb ansible_collections/community/ciscosmb
git clone --depth=1 --single-branch https://github.com/ansible-collections/ansible.netcommon.git ansible_collections/ansible/netcommon

cd ansible_collections/community/ciscosmb

python3 -m venv .venv
. .venv/bin/activate

pip install ansible
pip install -r requirements-dev.txt
pip install -r tests/unit/requirements.txt

```

### Develop

```
cd ansible_collections/community/ciscosmb
git pull
. .venv/bin/activate

# edit files
vim file
cp changelogs/fragments/.keep changelogs/fragments/featureXYZ.yml
vim changelogs/fragments/featureXYZ.yml

# test your changes see "Testing"

git commit -m "xxx" file
```

### Testing

```
cd ansible_collections/community/ciscosmb
. .venv/bin/activate

# PY="--python 3.8" # set your version or unset
METHOD="--docker" # or --local if you have no Docker installed
ansible-test sanity ${METHOD} ${PY}  \
    && ansible-test units  ${METHOD} ${PY} \
    && rm -f ./community-ciscosmb-*.tar.gz  \
    && ansible-galaxy collection build -v --force  \
    && export GALAXY_IMPORTER_CONFIG=./galaxy-importer.cfg  \
    && python3 -m galaxy_importer.main ./community-ciscosmb-*.tar.gz  \
    && rm -f ./community-ciscosmb-*.tar.gz
```

### Release

```
cd ansible_collections/community/ciscosmb
git pull
. .venv/bin/activate

# edit version x.y.z. in galaxy.yml
vim galaxy.yml

# edit changelog fragments (template in changelogs/fragments/.keep)
cp changelogs/fragments/.keep changelogs/fragments/release-x.y.z.yml
vim changelogs/fragments/release-x.y.z.yml

# change and generate CHANGELOG.rst
antsibull-changelog lint -v
antsibull-changelog release -v

git commit -m "version bump to x.y.z" .
git tag x.y.z
git push
```

## Releasing, Versioning and Deprecation

See [RELEASE_POLICY.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/RELEASE_POLICY.md)

## Code of Conduct

See [CODE_OF_CONDUCT.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/CODE_OF_CONDUCT.md)

## Contributing

See [CONTRIBUTING.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/CONTRIBUTING.md)

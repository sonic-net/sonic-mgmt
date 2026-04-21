## Local Development and testing

We accept all kinds of contributions, whether they are bug fixes, pull requests or documentation updates!

If you want to develop new content for this collection or improve what is already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATH`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

For example, if you are working in the `~/dev` directory:

```
cd ~/dev
git clone https://github.com/telekom_mms/ansible-collection-icinga-director collections/ansible_collections/telekom_mms/icinga_director
export ANSIBLE_COLLECTIONS_PATH=$(pwd)/collections:$ANSIBLE_COLLECTIONS_PATH
```

You can find more information in the [developer guide for collections](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections), and in the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).


### Linting with tox

After making code changes, please run the linters and fix all errors:

```
> tox -elinters
```

### Updating the tests and examples and runtime

If you add new features or arguments to the existing modules, please add them to the examples in the module itself.
The integration tests and examples in our documentation are then generated from the module-examples.

To trigger this generation, you need to run the script `hacking/update_examples_and_tests.sh` from the root of the repository. For this you need to have yq in version v3.4.1 installed (see https://mikefarah.gitbook.io/yq/v/v3.x/).

Download example:
```
> sudo wget https://github.com/mikefarah/yq/releases/download/3.4.1/yq_linux_amd64 -O /usr/bin/yq ; sudo chmod 755 /usr/bin/yq
```

If you add a new module, be sure to add it to the `action_groups` in the `meta/runtime.yml`-file.

### Integration tests with docker

```
# run icinga in a container and forward port 80
# username: icingaadmin password: icinga
> docker run --name icinga -d -p 80:80 ghcr.io/telekom-mms/icinga2:master


# run ansible-test
> ansible-test integration

# alternatively run the test playbooks against the container
> ansible-playbook tests/integration/targets/icinga/normalmode.yml
> ansible-playbook tests/integration/targets/icinga/checkmode.yml
```

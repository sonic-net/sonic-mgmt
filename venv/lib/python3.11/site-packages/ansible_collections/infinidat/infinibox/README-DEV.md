# Infinidat's Ansible Collection Development

## RHEL 8.9 Only
Installing Ansible using pip from within a venv caused an error much later in the dev process.  When installing a collection built in this environment this error occurred:
```
$ make galaxy-collection-install-locally
================ [ Begin galaxy-collection-install-locally ] ================
ansible-galaxy collection install --force infinidat-infinibox-1.4.0.tar.gz --collections-path $HOME/.ansible/collections
Starting galaxy collection install process
Process install dependency map
Starting collection install process
Installing 'infinidat.infinibox:1.4.0' to '/home/stack/.ansible/collections/ansible_collections/infinidat/infinibox'
ERROR! Unexpected Exception, this is probably a bug: "linkname 'venv/lib/python3.8/site-packages/ansible_test/_data/injector/python.py' not found"
```

Therefor using a venv is not recommended.  Instead use the following that will install ansible commands into `~/.local/bin`.
```
$ python3 -m pip install --user ansible
$ export PATH=/home/stack/.local/bin:$PATH
```
The boolean logic in the '_test-venv' recipe may need to be inverted if not using a venv.

## Ubuntu
Using a venv works as expected and is recommended.


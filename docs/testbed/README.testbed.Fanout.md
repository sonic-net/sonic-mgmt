# Fanout Credentials

To deploy fanout, use the ansible playbook [fanout playbook](ansible/fanout.yml), during the execution, credentials will be read as group variables and used.

To define its passwords, there are several ways. When tacacs is enabled and all fanout devices use the same credential, set fanout_tacacs_user/password (it will override everything). When tacacs is enabled but different type of devices use different credentials, do not set fanout_tacacs_user/password but fanout_tacacs_{OS}_user/password. When instead tacacs is not enabled and fanout uses local authentication, do not set tacacs password for that type of device and set its local user name and passwords.

Local credential names have been set arbitrarily and is listed below. Sonic devices use fanout_sonic_user/password, eos devices and mlnx devices use fanout_mlnx_user/password. Eos devices are special and will be discussed below.

Eos devices are different in that we want it to have 2 sets of credentials, one for accessing eos network configurations and one for accessing eos shell. Ansible playbook will have both network and shell accounts setup before running setup, but the shell credential is transient, and the playbook will make it persistent. Shell credential is read from fanout_admin_user/password to login to eos shell, and a template is put in place to make fanout_admin_user/password persistent shell account on eos. Network related credentials are not used in fanout playbook so far, but if it is, it should be tacacs credentials like the others or local credential fanout_network_user/password.

Pytest is another place where group variables are read to access fanout. Credential setup are similar for sonic and mlnx devices but different for eos. When test is run, we expect eos to have 2 sets of credentials already. Pytest will read fanout_network_user/password as network credential and fanout_shell_user/password as shell credential. When tacacs credential is set, it overrides local network credential but not shell credential.

## Root fanout selection

For connection graphs containing multiple root fanouts, set `root_fanout` to the
hostname of the root connected to the target leaf or test-server data port. The
value must name a `FanoutRoot` in the selected connection graph.

Set it in the leaf's host variables for `fanout.yml`, and in the test server's
host variables for `fanout_connect.yml`. The latter is called by
`testbed-cli.sh add-topo`, `connect-topo`, and `renumber-topo`.

For example:

```yaml
root_fanout: root-fanout-01
```

It can also be supplied with `-e root_fanout=<hostname>` for a deployment.

If `root_fanout` is not specified, the original selection logic is used: iterate
over all devices in the selected connection graph and assign `root_dev` and its
connection settings for each device whose type is `FanoutRoot`. The last matching
device in graph iteration order is selected, and only that root receives the
VLAN configuration. This logic assumes one root per graph; it does not select a
root based on the leaf or server's physical connections.

## SONiC 202605 fanout deployment

202605 images have a separate dispatcher block and use
`tasks/sonic/fanout_sonic_202605.yml` with `templates/sonic_deploy_202605.j2`.
The 202605 task file is a symbolic link to the shared 202511 task sequence;
the 202605 include supplies its own template name. The 202605 template adds
explicit RS FEC for 800G ports.

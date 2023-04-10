# Fanout Credentials

To deploy fanout, use the ansible playbook [fanout playbook](ansible/fanout.yml), during the execution, credentials will be read as group variables and used. 

To define its passwords, there are several ways. When tacacs is enabled and all fanout devices use the same credential, set fanout_tacacs_user/password (it will override everything). When tacacs is enabled but different type of devices use different credentials, do not set fanout_tacacs_user/password but fanout_tacacs_{OS}_user/password. When instead tacacs is not enabled and fanout uses local authentication, do not set tacacs password for that type of device and set its local user name and passwords.

Local credential names have been set arbitrarily and is listed below. Sonic devices use fanout_sonic_user/password, eos devices and mlnx devices use fanout_mlnx_user/password. Eos devices are special and will be discussed below.

Eos devices are different in that we want it to have 2 sets of credentials, one for accessing eos network configurations and one for accessing eos shell. Ansible playbook will have both network and shell accounts setup before running setup, but the shell credential is transient, and the playbook will make it persistent. Shell credential is read from fanout_admin_user/password to login to eos shell, and a template is put in place to make fanout_admin_user/password persistent shell account on eos. Network related credentials are not used in fanout playbook so far, but if it is, it should be tacacs credentials like the others or local credential fanout_network_user/password.

Pytest is another place where group variables are read to access fanout. Credential setup are similar for sonic and mlnx devices but different for eos. When test is run, we expect eos to have 2 sets of credentials already. Pytest will read fanout_network_user/password as network credential and fanout_shell_user/password as shell credential. When tacacs credential is set, it overrides local network credential but not shell credential.

# What is MCX

MCX is the combination of Mx and C0, a management devices that provides console access to network devices (DUT, fanout) and BMC access to servers (TODO).

# Configuring MCX

There is an ansible playbook mcx.yml under directory ansible that help you deploy your mcx.

First register the mcx devices and devices under its manegement to sonic_{inventory}_devices.csv, e.g.

```csv
management-1,192.168.10.3/23,Sonic,MgmtTsToRRouter,,sonic
```

Second mark the console links between mcx and network devices in sonic_{inventory}_console_links.csv with their baud rate, e.g.

```csv
management-1,13,str-acs-serv-01,ssh,root,9600
```

Third, create a group in inventory called mgmt, any device that provides management functions can go in there, like console servers, bmc servers, mcx and more. Examples can be seen in ansible/lab.

Lastly, generate connection graph with create_graph.py tool and run mcx.yml ansible playbook, e.g.

```
ansible-playbook mcx.yml -i lab --limit str-7215-10 -b --vault-password-file ~/password.txt
```

Add -e "reset=y" to replace config_db.json with new one (otherwise new config will only be added). Add -e "dry_run=y" for a preview of the new config_db.json. A new config_db.json will be generated and loaded and the old config_db.json will be backed up.

# mcx.yml

mcx.yml provides 2 kinds of deployment. Incremental update will add additional console link information to the devices and leave all others as they are. Reset update will replace config_db.json with new config_db.json with some necessary init config along with console links information. Reset update only supports Nokia-7215 and Celestica-E1031 so far. With no option provided, the playbook will default to incremental update. To use reset update, add -e "reset=y" to ansible-playbook command.

# Incremental Update

Incremental update currently uses sonic-cfggen to add additional config to config db, which does not support removing entry from config db. For versions 202205 and beyond, we will switch to GCU in the future.

# Dry Run

Since modification to config_db.json might be difficult to reverse. We provided a dry-run option, with -e "dry_run=y". It doesn't modify config_db.json but prints the new config_db.json.

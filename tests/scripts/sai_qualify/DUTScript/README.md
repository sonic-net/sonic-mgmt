# DUT Script

## pull_saiserver_syncd_rpc_dockers.sh

This script will pull the saiserver and syncd_rpc docker to your local docker registry.
After the pull, it will tag the image as a local image, for example for broadcom platform they will be
docker-saiserver-brcm
docker-syncd-brcm-rpc
the origin one can be in format like
acs-repo.corp.microsoft.com:5001/docker-saiserver-brcm:master.39085-dirty-20210923.145659

For how to get the OS version and asic name you can run the command
```
show version
```
Or check with existing docker images
```
docker images
```
Besides in the shell Utils.sh also contains some sample code for how to get those information.

*Please note, the pull process will depends on the OS version and shorten ASIC name, that means the docker with the OS version number and the asic name must be published to docker registry at first. It they are not publish, you need to pull them down manually.*

For start saiserver you can use the command
1. pull related dockers
```
sudo pull_saiserver_syncd_rpc_dockers.sh
```
2. prepare saiserver services
```
sudo prepare_saiserver_service.sh
```
3. start service
```
sudo systemctl start saiserver
```
4. You can control the saiserver inside the saiserver with commands
```
/usr/bin/start.sh
/usr/sbin/saiserver -p /usr/share/sonic/hwsku/sai.profile -f /usr/share/sonic/hwsku/port_config.ini
```

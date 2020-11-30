# Docker Container Setup
Use the `setup-container.sh` script to automatically create and configure your sonic-mgmt Docker container. You should run this script as the user that will be using the created container.

```
Usage ./setup-container.sh [options]
Options with (*) are required
-h -?                 : get this help

-n <container name>   : (*) set the name of the Docker container

-i <image ID>         : specify Docker image to use. This can be an image ID (hashed value) or an image name.
                      | If no value is provided, defaults to the following images in the specified order:
                      |   1. The local image named \"docker-sonic-mgmt\"
                      |   2. The local image named \"sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt\"
                      |   3. The remote image at \"sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt\"

-d <directory>        : specify directory inside container to bind mount to sonic-mgmt root (default "/var/src/")
```

After running the script, you should be able to enter the container using the `-u` option and your username:

```
docker exec -u <user> -it <container name> bash
```

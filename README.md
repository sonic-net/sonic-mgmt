# Software for Open Networking in the Cloud - SONiC
# Management

# Description
Tools for managing, configuring and monitoring SONiC

# CII Best Practices
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3933/badge)](https://bestpractices.coreinfrastructure.org/projects/3933)

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

# Contribution guide
All contributors must sign a contribution license agreement before contributions can be accepted.  
[How to become a contributer](https://github.com/Azure/SONiC/wiki/Becoming-a-contributor)
 


### GitHub Workflow

We're following basic GitHub Flow. If you have no idea what we're talking about, check out [GitHub's official guide](https://guides.github.com/introduction/flow/). Note that merge is only performed by the repository maintainer.

Guide for performing commits:

* Isolate each commit to one component/bugfix/issue/feature
* Use a standard commit message format:

>     [component/folder touched]: Description intent of your changes
> 
>     [List of changes]
>     
> 	  Signed-off-by: Your Name your@email.com
    
For example:

>     swss-common: Stabilize the ConsumerTable
>     
>     * Fixing autoreconf
>     * Fixing unit-tests by adding checkers and initialize the DB before start
>     * Adding the ability to select from multiple channels
>     * Health-Monitor - The idea of the patch is that if something went wrong with the notification channel, 
>       we will have the option to know about it (Query the LLEN table length).
>       
>       Signed-off-by: user@dev.null


* Each developer should fork this repository and [add the team as a Contributor](https://help.github.com/articles/adding-collaborators-to-a-personal-repository)
* Push your changes to your private fork and do "pull-request" to this repository
* Use a pull request to do code review
* Use issues to keep track of what is going on

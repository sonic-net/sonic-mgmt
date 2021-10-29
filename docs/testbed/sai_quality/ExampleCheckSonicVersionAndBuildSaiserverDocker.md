In this article, you will get known how to get a saiserver docker and get a builder to build saiserver binary

1. Check SONiC version in a DUT
**Old version might hit some issue caused by related package upgrade, you can always use the latest tag of a major version(i.e major is 20201231) but notice the matching image version.**
   ```
   show version

   SONiC Software Version: SONiC.20201231.39
   ```
2.  In your dev envrironment, install prerequirment lib, e.g. pip and jinja, re-located code to that tag and resident on a new branch, 
here we use repository [sonic-buildimage](https://github.com/Azure/sonic-buildimage)
Follow the doc at [Check SAI header version and SONiC branch](https://github.com/Azure/sonic-mgmt/blob/master/docs/testbed/sai_quality/CheckSAIHeaderVersionAndSONiCBranch.md)
    ```	
    # git checkout tags/<tag> -b <branch>
    # Example:

    git checkout tags/20201231.39 -b richardyu/20201231-39
    ```
    *note: Check submodule recursively*
    ```
    git submodule update --init --recursive

    # Execute make init once after cloning the repo, or after fetching remote repo with submodule updates

    make init
    ```
    *Note: Follow the resource to get how to build a binary and docker*
   [GitHub - Azure/sonic-buildimage: Scripts which perform an installable binary image build for SONiC](https://github.com/Azure/sonic-buildimage)

3. Start a local build
   ```
   # Clean environment as needed
   make reset
   # Init env
   make init
   # NOSTRETCH=y : Current image is buster
   # KEEP_SLAVE_ON=yes: Keeps slave container up and active after building process concludes.
   #setup environment as broadcom flatform
   make configure PLATFORM=broadcom
   #start build
   NOSTRETCH=y NOJESSIE=y KEEP_SLAVE_ON=yes ENABLE_SYNCD_RPC=y make target/debs/buster/saiserver_0.9.4_amd64.deb
   ```
   **You can get this build target by running command like(adjust as needed): NOSTRETCH=y NOJESSIE=y ENABLE_SYNCD_RPC=y make list**


4. Wait for the build process 
5. In the end, you will get something like this, and prompt as below (inside docker)
   ```
   # Check if thrift installed
   richardyu@a0363ed6ca36:/sonic$ thrift
   Usage: thrift [options] file

   Use thrift -help for a list of options
   ```
6. Keep this terminal and start another terminal, login the same host
 - Check the docker, the builder appears with the name as sonic-slave-***, it always the recently created one
   ```
   docker ps
   CONTAINER ID   IMAGE                                                 COMMAND                  CREATED          STATUS          
   PORTS                                     NAMES
   e1df2df072c4   sonic-slave-buster-richardyu:86ef76a28e6              "bash -c 'make -f sl…"   36 minutes ago   Up 36 minutes   
   22/tcp                                         condescending_lovelace
   ```
 - Commit that docker as a saiserver-docker builder for other bugging or related resource building usages.
   ```
   docker commit <docker_name> <docker_image>:<tag>
   docker commit condescending_lovelace saisever-builder-20201231-39:0.0.1
   ```
7. Then, exit from the docker above (console as 'richardyu@e1df2df072c4'), you can get your buildout artifacts in folder `./target`, there also contains the logs, and other accessories
8. For building the saiserver binary, you can mount your local SAI repository to that docker and just start that docker for your building purpose.
   ```
   # SAI repo is located inside local /code folder
   docker run --name saisever-builder-20201231-39 -v  /code:/data -di saisever-builder-20201231-39:0.0.1 bash
   ```
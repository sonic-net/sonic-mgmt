In this article, you will get known how to get a saiserver docker and get a builder to build saiserver binary

1. Check SONiC version in a DUT
   ```
   show version
   
   SONiC Software Version: SONiC.20201231.08
   ```
   
2. In your dev envrironment, re-located code to that tag and resident on a new branch, 
   here we use repository[Azure/sonic-mgmt: Configuration management examples for SONiC](https://github.com/Azure/sonic-mgmt)
   
   Getting a sonic version matched SAI Header version, please follow the doc at [Check SAI header version and SONiC branch](./CheckSAIHeaderVersionAndSONiCBranch.md)

   ```	
   git checkout tags/<tag> -b <branch>
   
   Example:
   git checkout tags/20201231.08 -b richardyu/20201231-08
   ```
   *note: Check submodule recursively*

   ```
   git submodule update --init --recursive
   ```
   *Note: Follow the resource to get how to build a binary and docker*
   [GitHub - Azure/sonic-buildimage: Scripts which perform an installable binary image build for SONiC](https://github.com/Azure/sonic-buildimage)

3. Start a local build
   ```
   make configure PLATFORM=broadcom
   NOSTRETCH=y KEEP_SLAVE_ON=yes make target/docker-saiserver-brcm.gz
   
   NOSTRETCH=y : Current image is buster
   KEEP_SALVE_ON=yes: Keeps slave container up and active after building process concludes.
   ```


4. Wait for the build process 
5. In the end, you will get something like this, and prompt as below (inside docker)
   ```
   [ 01 ] [ target/docker-saiserver-brcm.gz ]
   7e28d9702f570fdb94c8c530a9bf1f3feac0a113737d013b89ebc3dedc48470f
   richardyu@e1df2df072c4:/sonic$
   ```
6. In the same host, outside the docker above
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
   docker commit condescending_lovelace saisever-builder-20201231-08:0.0.1
   ```
7. Then, exit from the docker above (console as 'richardyu@e1df2df072c4'), you can get your buildout artifacts in folder `./target`, there also contains the logs, and other accessories
8. For building the saiserver binary, you can mount your local SAI repository to that docker and just start that docker for your building purpose.
   ```
   #SAI repo is located inside local /code folder
   docker run --name saisever-builder-20201231-08 -v  /code:/data -di saisever-builder-20201231-08:0.0.1 bash
   ```
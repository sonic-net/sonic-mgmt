# Prerequisites
* An Ubuntu Linux box
* The sonic docker image in your home directory.
  * Pre-built sonic-mgmt can also be downloaded from [here](https://sonic-jenkins.westus2.cloudapp.azure.com/job/bldenv/job/docker-sonic-mgmt/lastSuccessfulBuild/artifact/sonic-buildimage/target/docker-sonic-mgmt.gz)
* Basic knowledge of docker commands.
* Docker-tools should be there installed in your system.
# sonic-mgmt docker environment preparation: useful commands (for Ubuntu system)
**Installing docker**<br>
``sudo apt-get update``<br>
``sudo apt-get remove docker docker-engine docker.io``<br>
``sudo apt install docker.io``<br>
``sudo systemctl start docker``<br>
``sudo systemctl enable docker``<br><br>
**Unzip sonic Image**<br>
``gzip -d docker-sonic-mgmt.gz``<br><br>
**Load the docker Image**<br>
``sudo docker images``<br>
``sudo docker load -i docker-sonic-mgmt``<br>
``sudo docker run -it --name sonic docker-sonic-mgmt``<br><br>
**Stopping a docer session**<br>
``sudo docker stop sonic``<br><br>
**Reconnect to a stopped docer session**<br>
``sudo docker start -i sonic``<br><br>
**When you are done you may remove the image sonic**<br>
``sudo docker rm sonic``<br><br>
**Remove docker by image Id**<br>
``sudo docker rmi -f <image-id>``<br><br>
**Running a sonic docker with local directoy mounted in it.**<br>
``sudo docker run -it --name sonic --privileged -v /home/ubuntu/adhar/:/var/johnar/adhar --workdir /var/johnar/adhar --user johnar:gjohnar docker-sonic-mgmt``<br><br>


# How to run a docker with a port number
**Run a docker container with port number -p**<br>
* -itd will run docker in a detached state, I'm using port 2222 you can use any port<br>
``sudo docker run -itd --name sonic -p 2222:22 docker-sonic-mgmt``<br><br>

**Enter the docker container using exec**<br>
``sudo docker exec -it sonic bash``<br><br>

**Check ssh service is running inside the docker**<br>
``johnar@1ed3a9afe70f:~$ service --status-all``<br><br>

**If ssh service is not running start ssh**<br>
``johnar@1ed3a9afe70f:~$ sudo service ssh start``<br><br>

**update johnar user passwd**<br>
* update passwd of your choice
``johnar@1ed3a9afe70f:~$ sudo passwd johnar``<br><br>

**use ssh from any machine in the network to login to docker directly**<br>
``ssh johnar@10.39.71.246 -p 2222``

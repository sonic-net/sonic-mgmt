# gnmitest Service Docker Image

This directory contains files required to build a Docker image for gnmitest
service.

This is not an official Google product.

## Launching the Docker Image

To run the gNMI test service simply execute `run.sh` on a system running the 
Docker daemon. By default:

 * `gnmitest_demo` is configured to run at tcp/55555 port. It can be 
    connected using the `gnmitest_cli` command-line tool with the address 
   `localhost:55555`.

   ```
   gnmitest_cli --address localhost:55555 --suite_text_proto=testdata/suite.textproto
   ```

 * `gnmitest_demo` also starts a fake gNMI agent at tcp/55556 port. This port
   can only be accessed inside the container. If fake gNMI agent intended to be
   used in Suite proto as a target, address field of the Connection message
   should be set as `localhost:55556` in Suite proto.

 * fake gNMI agent sends the gNMI SubscribeResponse messages given inside
   `targetA.textproto` file. If you modify textproto file, make sure to restart
   docker container.

## Building Docker Image

To rebuild the `gnmitest_demo` binary, and rebuild the Docker image, execute
the `build.sh` script.

## Image on Docker Hub

This image can be pulled from Docker Hub using:

```
docker pull openconfig/gnmitest_demo
```

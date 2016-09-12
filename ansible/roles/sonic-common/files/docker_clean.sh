#!/bin/bash

# Clean up untagged docker images, ie. '<none>:<none>'
docker images -q --filter "dangling=true" | xargs --no-run-if-empty docker rmi

# Clean up unused docker images, but ignore untagged docker images
# Note:
#   if there is no tag or repository for one image, it will shows as 'repository:<none>'
#   or '<none>:TAG' or '<none>:<none>'
# docker ps ...:
#   list all used image
# docker images ...:
#   list all images by tag and by digest
# grep -xvf A B:
#   exclude all lines from file B matching any whole line in file A
grep -xvf <(docker ps -a --format {{.Image}}) <(docker images --format '{{.Repository}}:{{.Tag}}\n{{.Repository}}@{{.Digest}}' | grep -v '<none>') | xargs --no-run-if-empty docker rmi

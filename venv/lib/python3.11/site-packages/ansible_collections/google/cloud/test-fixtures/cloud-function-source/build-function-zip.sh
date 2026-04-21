#!/usr/bin/env bash
# Build the cloud function zip file,
# in the desired cloud function source format.
if [ -f ../cloud-function.zip ]; then
    rm ../cloud-function.zip
fi
zip ../cloud-function.zip ./*
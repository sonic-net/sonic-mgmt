#!/bin/bash

BUFFER_MODEL=$(sonic-db-cli -s CONFIG_DB hget "DEVICE_METADATA|localhost" buffer_model)

if [[ "$BUFFER_MODEL" == "dynamic" ]]; then
    exit 0
else
    exit 1
fi

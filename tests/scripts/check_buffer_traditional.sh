#!/bin/bash

BUFFER_MODEL=$(redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model)

if [[ "$BUFFER_MODEL" != "dynamic" ]]; then
    exit 0
else
    exit 1
fi

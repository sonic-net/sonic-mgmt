#!/bin/bash

# This file will be copied into syncd-rpc container for debugging within syncd-rpc

# shell for init syncd rpc container.
# when start syncd-rpc for debugging,
# we need to use this shell to control syncd start process
/usr/bin/start.sh
. /usr/bin/syncd_init_common.sh
config_syncd

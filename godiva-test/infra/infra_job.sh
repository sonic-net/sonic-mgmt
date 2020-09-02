#!/bin/bash

# DIR should be the root directory, parent of infra
# however, this needs to be cleaned up in the script before
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pytest -s ${DIR}/infra/infra_ap.py \
    --selective-test-file=${DIR}/selective_test_file.txt \
    --topology-file "${DIR}/../th3_4_topo.json" \
    --tb=short \
    --test-input-file="${DIR}/../gd_input_file.json" \
    --mail-to=godiva-mgbl@cisco.com \
    --mail-from=no-reply@cisco.com \
    --debug-enable \
    -m 'not Future' \
    -p no:cacheprovider

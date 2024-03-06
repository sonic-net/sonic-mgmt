#!/bin/bash
#
# PROPRIETARY AND CONFIDENTIAL. Cisco Systems, Inc. considers the contents of this
# file to be highly confidential trade secret information.
#
# COPYRIGHT 2023-2024 Cisco Systems, Inc., All rights reserved.

if [[ -z "${WS_ROOT}" ]]; then
    echo "Must execute from Tortuga source workspace"
    exit 1
fi

DIR="${WS_ROOT}/sandbox/sonic-tests"

# Make a temp directory.
mkdir -p "${DIR}/sandbox/certs"

# Build a static Linux binary of config-gen.
pushd "${WS_ROOT}/cloud/tools/config-gen" || exit
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "${DIR}/config-gen"
popd || exit

cp "${WS_ROOT}/cloud/tests/for-sonic-team/"* "${DIR}/"
cp "${WS_ROOT}/cloud/tests/pyvxr/get_ports.sh" "${DIR}/"
cp "${WS_ROOT}/cloud/tests/pyvxr/reset_sim.sh" "${DIR}/"
cp "${WS_ROOT}/cloud/tests/pyvxr/sl1x3-ref-sim.yaml" "${DIR}/sonic-ref-sim.yaml"
cp "${WS_ROOT}/cloud/tests/pyvxr/mesh3-ref-sim.yaml" "${DIR}/mesh3-ref-sim.yaml"
cp "${WS_ROOT}/cloud/tests/pyvxr/sl1x3-ref-sim.yaml" "${DIR}/sl1x3-ref-sim.yaml"
cp "${WS_ROOT}/cloud/tests/pyvxr/sl2x2-ref-sim.yaml" "${DIR}/sl2x2-ref-sim.yaml"
cp "${WS_ROOT}/cloud/tests/pyvxr/sl2x3-ref-sim.yaml" "${DIR}/sl2x3-ref-sim.yaml"
cp "${WS_ROOT}/sandbox/certs/cloud.crt" "${DIR}/sandbox/certs/cloud.crt"
cp "${WS_ROOT}/sandbox/certs/service.key" "${DIR}/sandbox/certs/service.key"

tar -C "${DIR}" -cvzf "${WS_ROOT}/sandbox/sonic-tests-$(cat ${WS_ROOT}/sandbox/tortuga_agent_version).tar.gz" .

#!/bin/bash
set -euo pipefail

codename="${1:?Debian codename is required}"
architecture="${2:?Debian architecture is required}"
python_abi="${3:?Python ABI is required}"
output="${4:?Output tarball path is required}"

case "$codename" in
    bookworm|trixie) ;;
    *) echo "Unsupported syncd Debian codename: $codename" >&2; exit 1 ;;
esac
if [[ "$architecture" != "amd64" ]]; then
    echo "Unsupported syncd architecture: $architecture" >&2
    exit 1
fi
if [[ ! "$python_abi" =~ ^cp[0-9]+$ ]]; then
    echo "Invalid Python ABI: $python_abi" >&2
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
output_dir="$(cd -- "$(dirname -- "$output")" && pwd)"
output="$output_dir/$(basename -- "$output")"
container="copp-nn-agent-builder-$$-$RANDOM"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ptf_commit="9d41838d634c479fc24fac7a527ec5ee2d0ce8eb"
nnpy_version="1.4.2"
cffi_version="2.1.1"
pycparser_version="3.0"
wheel_version="0.45.1"

docker create \
    --platform linux/amd64 \
    --name "$container" \
    -e DEBIAN_FRONTEND=noninteractive \
    -e "EXPECTED_CODENAME=$codename" \
    -e "EXPECTED_ARCHITECTURE=$architecture" \
    -e "EXPECTED_PYTHON_ABI=$python_abi" \
    -e "PTF_COMMIT=$ptf_commit" \
    -e "NNPY_VERSION=$nnpy_version" \
    -e "CFFI_VERSION=$cffi_version" \
    -e "PYCPARSER_VERSION=$pycparser_version" \
    -e "WHEEL_VERSION=$wheel_version" \
    "debian:${codename}-slim" \
    bash -euxo pipefail -c '
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            build-essential ca-certificates curl libffi-dev libnanomsg-dev \
            python3 python3-dev python3-venv

        actual_architecture="$(dpkg --print-architecture)"
        actual_python_abi="cp$(python3 -c \
            "import sys; print(\"{}{}\".format(*sys.version_info[:2]))")"
        test "$actual_architecture" = "$EXPECTED_ARCHITECTURE"
        test "$actual_python_abi" = "$EXPECTED_PYTHON_ABI"

        work_dir="$(mktemp -d)"
        bundle_dir="$work_dir/copp-nn-agent-bundle"
        mkdir -p "$bundle_dir/lib" "$bundle_dir/python" \
            "$bundle_dir/ptf" "$bundle_dir/licenses" "$work_dir/wheels"

        python3 -m venv "$work_dir/venv"
        "$work_dir/venv/bin/pip" install --quiet --no-cache-dir \
            "wheel==$WHEEL_VERSION"
        "$work_dir/venv/bin/pip" wheel --quiet --no-cache-dir \
            --no-binary nnpy,cffi --wheel-dir "$work_dir/wheels" \
            "nnpy==$NNPY_VERSION" "cffi==$CFFI_VERSION" \
            "pycparser==$PYCPARSER_VERSION"
        python3 - "$work_dir/wheels" "$bundle_dir/python" <<"PY"
import pathlib
import sys
import zipfile

wheel_dir = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
for wheel in sorted(wheel_dir.glob("*.whl")):
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(destination)
PY

        (cd "$bundle_dir/lib" && apt-get download -qq libnanomsg5)
        curl -fsSL -o "$bundle_dir/ptf_nn_agent.py" \
            "https://raw.githubusercontent.com/p4lang/ptf/$PTF_COMMIT/ptf_nn/ptf_nn_agent.py"
        curl -fsSL -o "$bundle_dir/ptf/afpacket.py" \
            "https://raw.githubusercontent.com/p4lang/ptf/$PTF_COMMIT/src/ptf/afpacket.py"
        curl -fsSL -o "$bundle_dir/licenses/PTF-LICENSE" \
            "https://raw.githubusercontent.com/p4lang/ptf/$PTF_COMMIT/LICENSE"
        touch "$bundle_dir/ptf/__init__.py"
        install -m 0755 /tmp/install_nn_agent_bundle.sh \
            "$bundle_dir/install.sh"

        cat > "$bundle_dir/manifest.json" <<EOF
{
  "debian_codename": "$EXPECTED_CODENAME",
  "architecture": "$actual_architecture",
  "python_abi": "$actual_python_abi",
  "libnanomsg5": "$(dpkg-deb -f "$bundle_dir"/lib/libnanomsg5_*.deb Version)",
  "nnpy": "$NNPY_VERSION",
  "cffi": "$CFFI_VERSION",
  "pycparser": "$PYCPARSER_VERSION",
  "ptf_commit": "$PTF_COMMIT"
}
EOF
        printf "%s\n" "$EXPECTED_CODENAME" > "$bundle_dir/debian_codename"
        printf "%s\n" "$actual_architecture" > "$bundle_dir/architecture"
        printf "%s\n" "$actual_python_abi" > "$bundle_dir/python_abi"

        tar -czf /tmp/copp-nn-agent-bundle.tar.gz \
            -C "$work_dir" copp-nn-agent-bundle
    ' >/dev/null

docker cp "$script_dir/install_nn_agent_bundle.sh" \
    "$container:/tmp/install_nn_agent_bundle.sh"
docker start -a "$container"
docker cp "$container:/tmp/copp-nn-agent-bundle.tar.gz" "$output"

#!/bin/bash
set -euo pipefail

bundle_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
. /etc/os-release

actual_codename="${VERSION_CODENAME:-}"
actual_architecture="$(dpkg --print-architecture)"
actual_python_abi="cp$(python3 -c \
    'import sys; print("{}{}".format(*sys.version_info[:2]))')"
expected_codename="$(cat "$bundle_dir/debian_codename")"
expected_architecture="$(cat "$bundle_dir/architecture")"
expected_python_abi="$(cat "$bundle_dir/python_abi")"

if [[ "$actual_codename" != "$expected_codename" ]]; then
    echo "CoPP NN-agent bundle targets $expected_codename, not $actual_codename" >&2
    exit 1
fi
if [[ "$actual_architecture" != "$expected_architecture" ]]; then
    echo "CoPP NN-agent bundle targets $expected_architecture, not $actual_architecture" >&2
    exit 1
fi
if [[ "$actual_python_abi" != "$expected_python_abi" ]]; then
    echo "CoPP NN-agent bundle targets $expected_python_abi, not $actual_python_abi" >&2
    exit 1
fi

if ! ldconfig -p | grep -q 'libnanomsg\.so\.5'; then
    dpkg -i "$bundle_dir"/lib/libnanomsg5_*_"$actual_architecture".deb
    ldconfig
fi

site_dir="$(python3 -c 'import site; print(site.getsitepackages()[0])')"
cp -a "$bundle_dir/python/." "$site_dir/"
install -d -m 0755 /opt/ptf
install -m 0644 "$bundle_dir/ptf_nn_agent.py" /opt/ptf_nn_agent.py
install -m 0644 "$bundle_dir/ptf/__init__.py" \
    "$bundle_dir/ptf/afpacket.py" /opt/ptf/

python3 - <<'PY'
import nnpy
sock = nnpy.Socket(nnpy.AF_SP, nnpy.PAIR)
PY
python3 /opt/ptf_nn_agent.py --help >/dev/null

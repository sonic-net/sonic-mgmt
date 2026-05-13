"""
Testbed configuration registry.

Keyed by testbed YAML filename. Every tool (run_test.sh, spytest_run.py,
spytest_publish.py) imports or calls this module to look up config for a
given testbed YAML.

To add a new testbed: add an entry to TESTBED_CONFIGS below.
"""

from pathlib import Path

# Known repo directory names and their spytest sub-paths (for auto-discovery)
REPO_LAYOUT = {
    "sonic-test":     "sonic-mgmt/spytest",  # sonic-test/sonic-mgmt/spytest
    "oci-sonic-mgmt": "spytest",             # oci-sonic-mgmt/spytest
}

# ── Testbed configs keyed by YAML filename ────────────────────────────────
# Each entry carries everything the tools need so nothing is hardcoded elsewhere.
#
#   runner_platform  : platform arg passed to run_test.sh (selects docker image, test path, etc.)
#   profile_suffix   : used in log dir names and dashboard profile (e.g. "Tortuga", "Gamut", "OCI")
#   npu              : NPU/ASIC name for dashboard (e.g. "G200", "Q200", "SPECTRUM4")
#   base_config_dir  : subdirectory under base_configs/ to push; empty string = skip
#   docker_image     : docker image name (without tag) for container
#   docker_tar       : filename of docker tar (fetched from CONTAINER_SERVER)
#   container_prefix : container name = <prefix>_$USER
#   test_path        : test directory inside the container
#   fabric           : list of fabric types for dashboard, e.g. ["IPv4", "VXLAN"] or ["IPv6"]
#   input_file       : extra --env input_file=... for spytest (empty string = none)
#

# Server hosting container tar files (SCP'd to dev machine on first use)
CONTAINER_SERVER = {
    "host": "sonic-ucs-m6-51",
    "user": "sonic",
    "password": "roZes@123",
    "path": "/home/sonic/containers",
}

TESTBED_CONFIGS = {
    "tortuga_2x2_G200_testbed.yaml": {
        "runner_platform": "tortuga",
        "profile_suffix":  "Tortuga",
        "npu":             "G200",
        "base_config_dir": "laguna_2x2_configs",
        "docker_image":    "docker.io/library/ixia-container.10.25:latest",
        "docker_tar":      "ixia-container.10.25.tar.gz",
        "container_prefix": "ixia_10.25",
        "test_path":       "/data/tests/cisco/tortuga/qos",
        "fabric":          ["IPv4", "VXLAN"],
        "input_file":      "",
    },
    "tortuga_2x2_Q200_testbed.yaml": {
        "runner_platform": "tortuga",
        "profile_suffix":  "Tortuga",
        "npu":             "Q200",
        "base_config_dir": "carib_siren_2x2_configs",
        "docker_image":    "docker.io/library/ixia-container.10.25:latest",
        "docker_tar":      "ixia-container.10.25.tar.gz",
        "container_prefix": "ixia_10.25",
        "test_path":       "/data/tests/cisco/tortuga/qos",
        "fabric":          ["IPv4", "VXLAN"],
        "input_file":      "",
    },
    "gamut_2x2_qos.yaml": {
        "runner_platform": "gamut",
        "profile_suffix":  "Gamut",
        "npu":             "SPECTRUM4",
        "base_config_dir": "gamut_2x2_configs",
        "docker_image":    "localhost/spytest/keysight-u18:11.00",
        "docker_tar":      "keysight_11.00.tar.gz",
        "container_prefix": "keysight_11.00",
        "test_path":       "/data/tests/cisco/tortuga/qos",
        "fabric":          ["IPv4", "VXLAN"],
        "input_file":      "",
    },
    "rocev2_testbed.yaml": {
        "runner_platform": "oci",
        "profile_suffix":  "OCI",
        "npu":             "G200",
        "base_config_dir": "",
        "docker_image":    "localhost/ixia_11.10_rev2:latest",
        "docker_tar":      "ixia-11.10-rev2.tar.gz",
        "container_prefix": "ixia_11.10",
        "test_path":       "/data/tests/cisco/qos",
        "fabric":          ["IPv6"],
        "input_file":      "/data/tests/cisco/input_file/rocev2_input_file.yaml",
    },
}


def get_config(yaml_path):
    """Look up testbed config by YAML filename.

    Args:
        yaml_path: Full path or just filename of the testbed YAML.

    Returns:
        dict with all config keys, or None if not found.
    """
    filename = Path(yaml_path).name
    return TESTBED_CONFIGS.get(filename)


def discover_repo(yaml_path):
    """Walk up from a testbed YAML path to find the repo root and spytest dir.

    Returns (repo_dir: Path, spytest_dir: Path) or raises ValueError.
    """
    yaml_path = Path(yaml_path).resolve()
    for parent in yaml_path.parents:
        if parent.name in REPO_LAYOUT:
            spytest_dir = parent / REPO_LAYOUT[parent.name]
            if spytest_dir.is_dir():
                return parent, spytest_dir
    raise ValueError(
        f"Cannot find repo root from YAML path: {yaml_path}\n"
        f"Expected one of {list(REPO_LAYOUT.keys())} in the path."
    )


if __name__ == "__main__":
    # Quick self-test / listing
    import json, sys
    if len(sys.argv) > 1:
        cfg = get_config(sys.argv[1])
        if cfg:
            print(json.dumps(cfg, indent=2))
        else:
            print(f"Unknown testbed YAML: {sys.argv[1]}", file=sys.stderr)
            sys.exit(1)
    else:
        for name, cfg in TESTBED_CONFIGS.items():
            print(f"  {name:45s}  platform={cfg['runner_platform']:8s}  npu={cfg['npu']:10s}  profile={cfg['profile_suffix']}")

"""Shared helpers for SONiC packet trimming tests.

Common to tests/packet_trimming/ and
tests/generic_config_updater/test_packet_trimming_buffer_profile.py.
"""

TRIMMING_BUFFER_PROFILE_CONFIG = {
    "pool": "egress_lossy_pool",
    "dynamic_th": "3",
    "size": "0",
    "packet_discard_action": "drop",
}


def buffer_profile_exists(duthost, profile_name):
    """Return True if the BUFFER_PROFILE entry exists in CONFIG_DB."""
    cmd = f"sonic-db-cli CONFIG_DB EXISTS 'BUFFER_PROFILE|{profile_name}'"
    return duthost.shell(cmd)["stdout"].strip() == "1"


def buffer_profile_has_field(duthost, profile_name, field):
    """Return True if the BUFFER_PROFILE entry has the given field set in CONFIG_DB."""
    cmd = f"sonic-db-cli CONFIG_DB HEXISTS 'BUFFER_PROFILE|{profile_name}' {field}"
    return duthost.shell(cmd)["stdout"].strip() == "1"

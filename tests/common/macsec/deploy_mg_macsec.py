"""
MACsec setup driven by minigraph per-interface configuration.

Provides setup_macsec_from_minigraph() for use in pytest fixtures or conftest
hooks that need MACsec already configured before tests run, without having to
pass profile parameters explicitly — the minigraph carries all required info.

The three steps match the reference setup_macsec_configuration() in
macsec_config_helper.py, reusing all the same primitives.
"""
import json
import logging
import os
import time
from collections import defaultdict

from tests.common.macsec.macsec_config_helper import (
    enable_macsec_feature,
    enable_macsec_port,
    set_macsec_profile,
)
from tests.common.macsec.macsec_helper import submit_async_task, wait_all_complete
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

_PROFILE_JSON = os.path.join(os.path.dirname(__file__), "profile.json")


def _load_profile(name):
    """Return a profile dict from profile.json with 'name' key added."""
    with open(_PROFILE_JSON) as f:
        profiles = json.load(f)
    if name not in profiles:
        raise KeyError(
            "Unknown MACsec profile '{}'. Valid profiles: {}".format(
                name, sorted(profiles.keys())
            )
        )
    p = dict(profiles[name])
    p.setdefault("rekey_period", 0)
    p["name"] = name
    return p


def setup_macsec_from_minigraph(duthost, nbrhosts, tbinfo):
    """Configure MACsec on all interfaces declared in the minigraph.

    Reads minigraph_macsec_links from the DUT's minigraph facts. For each
    MACsec-enabled link the minigraph carries both the neighbor info and the
    profile name (referencing an entry in tests/common/macsec/profile.json).

    The setup follows the same three-step sequence as setup_macsec_configuration():
      1. Set profile in CONFIG_DB on both DUT and neighbor.
      2. Enable profile on each port (both sides) with 3-second gaps.
      3. Wait up to 300 s for STATE_DB MACSEC_PORT_TABLE.state == ok on DUT
         and mac security controlledPort == true on EOS neighbor.

    DUT always gets profile['priority']. Neighbors alternate between
    priority-1 (even index) and priority+1 (odd index) to ensure the DUT is
    elected MKA key-server.

    After all ports are up a 60-second hold allows LACP/BGP to recover from
    any link flap caused by enabling MACsec.

    Args:
        duthost:  SonicHost DUT object.
        nbrhosts: dict {nbr_name: {"host": host_obj, "conf": {...}}}.
        tbinfo:   testbed info dict (passed through to extended minigraph facts).

    Returns:
        ctrl_links dict {dut_port: {"name", "host", "port", "_profile"}}
        for use with macsec_config_helper cleanup functions.
        Empty dict if no MACsec links are declared in the minigraph.
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    macsec_links_fact = mg_facts.get("minigraph_macsec_links", {})
    if not macsec_links_fact:
        logger.info("No minigraph_macsec_links found — MACsec setup skipped")
        return {}

    # Build ctrl_links in the format expected by macsec_config_helper
    ctrl_links = {}
    for dut_port, link in macsec_links_fact.items():
        nbr_name = link["neighbor"]
        if nbr_name not in nbrhosts:
            logger.warning(
                "Neighbor '%s' for port %s not in nbrhosts — skipping",
                nbr_name, dut_port,
            )
            continue
        ctrl_links[dut_port] = {
            "name": nbr_name,
            "host": nbrhosts[nbr_name]["host"],
            "port": link["neighbor_port"],
            "_profile": link["profile"],
        }

    if not ctrl_links:
        return {}

    # Enable the MACsec feature container on DUT and all involved neighbors
    macsec_nbrhosts = {d["name"]: nbrhosts[d["name"]] for d in ctrl_links.values()}
    enable_macsec_feature(duthost, macsec_nbrhosts)

    # Group by profile name so profile DB entries are written once per profile
    by_profile = defaultdict(dict)
    for dut_port, nbr in ctrl_links.items():
        by_profile[nbr["_profile"]][dut_port] = nbr

    all_ctrl_links = {}
    for profile_name, subset in by_profile.items():
        profile = _load_profile(profile_name)

        # Step 1: set profile on DUT and neighbors in parallel
        logger.info("MACsec setup step 1: set profile '%s' on %d ports", profile_name, len(subset))
        for i, (dut_port, nbr) in enumerate(subset.items()):
            submit_async_task(set_macsec_profile, (
                duthost, dut_port, profile["name"], profile["priority"],
                profile["cipher_suite"], profile["primary_cak"],
                profile["primary_ckn"], profile["policy"],
                profile["send_sci"], profile["rekey_period"],
            ))
            nbr_priority = profile["priority"] - 1 if i % 2 == 0 else profile["priority"] + 1
            submit_async_task(set_macsec_profile, (
                nbr["host"], nbr["port"], profile["name"], nbr_priority,
                profile["cipher_suite"], profile["primary_cak"],
                profile["primary_ckn"], profile["policy"],
                profile["send_sci"], profile["rekey_period"],
            ))
        wait_all_complete(timeout=180)

        # Step 2: enable port on both sides with 3-second gaps between ports
        logger.info("MACsec setup step 2: enable ports for profile '%s'", profile_name)
        for dut_port, nbr in subset.items():
            time.sleep(3)
            submit_async_task(enable_macsec_port, (duthost, dut_port, profile["name"]))
            submit_async_task(enable_macsec_port, (nbr["host"], nbr["port"], profile["name"]))
        wait_all_complete(timeout=180)

        # Step 3: wait for both sides to report MACsec ready
        logger.info("MACsec setup step 3: waiting for ready on %d ports", len(subset))
        for dut_port, nbr in subset.items():
            assert wait_until(
                300, 3, 0,
                lambda dp=dut_port, n=nbr: (
                    duthost.iface_macsec_ok(dp) and n["host"].iface_macsec_ok(n["port"])
                ),
            ), "MACsec session did not come up on {} / {}:{}".format(
                dut_port, nbr["name"], nbr["port"]
            )

        all_ctrl_links.update(subset)

    # Hold time for LACP/BGP recovery after potential link flap
    time.sleep(60)
    logger.info("MACsec setup from minigraph complete (%d ports)", len(all_ctrl_links))
    return all_ctrl_links

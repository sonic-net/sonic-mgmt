"""
Validate per-feature selection of the SONiC-VPP sonic_ext plugin.

Features are turned off with SONIC_EXT_CONFIG in /etc/sonic/vpp/syncd_vpp_env,
which vpp_init.sh renders into a "sonic-ext { }" startup.conf stanza when the
syncd container starts. Two families are covered:

  VPP-wired     punt-via-member, host-xc, drop-member-stats (and the derived
                capture). Off means the node is never attached to its feature
                arc, so arc membership is asserted, not just the toggle.
  saivpp-wired  ip2me, l2-trap-fixup, l2-vlan-filter. VPP only stores these;
                saivpp queries them over sonic_ext_feature_get and skips the
                wiring, so the effect is asserted on the VPP graph/arcs and the
                cause on the saivpp NOTICE.

See sonic-net/sonic-platform-vpp#291 and sonic-net/sonic-sairedis#2089.
"""
import logging
import re

import pytest

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.plugins.loganalyzer.loganalyzer import DisableLogrotateAndWaitSyslogContext, LogAnalyzer
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.asic("vpp"),
]

SYNCD_VPP_ENV = "/etc/sonic/vpp/syncd_vpp_env"
SYNCD_VPP_ENV_BACKUP = "/etc/sonic/vpp/syncd_vpp_env.sonic_ext_test.bak"
VPPCTL = "docker exec syncd vppctl"

VPP_WIRED = ("punt-via-member", "host-xc", "drop-member-stats")
SAIVPP_WIRED = ("ip2me", "l2-trap-fixup", "l2-vlan-filter")
DEFAULT_STATE = {feature: "on" for feature in VPP_WIRED + SAIVPP_WIRED}

IP2ME_ACL_TABLE = "SONIC_EXT_IP2ME"
IP2ME_ACL_RULE = "RULE_1"
# Any deny rule makes saivpp want ip2me on the bound port; the match itself is irrelevant.
IP2ME_ACL_SRC_IP = "10.99.99.1/32"

SAIVPP_DISABLED_NOTICE_RE = r".*sonic-ext feature {} disabled in startup.conf.*"
SAIVPP_QUERY_FAILED_RE = r".*sonic_ext_feature_get\(.*\) failed; assuming enabled.*"

ARC_WAIT_TIMEOUT = 180
ARC_WAIT_INTERVAL = 10


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(rand_one_dut_hostname, loganalyzer):
    if loganalyzer:
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend([
            # Logged by VPP at ERR level whenever a saivpp-wired feature is off.
            r".*sonic_ext_apply_config.*awaiting saivpp query.*",
        ])


def vppctl(duthost, cmd):
    return duthost.shell("{} {}".format(VPPCTL, cmd))["stdout"]


def get_sonic_ext_state(duthost):
    """Parse the on/off toggles from 'show sonic-ext'; counters are skipped."""
    state = {}
    for line in vppctl(duthost, "show sonic-ext").splitlines():
        m = re.match(r"^\s*([a-z0-9-]+(?: \(derived\))?)\s*:\s*(on|off)\s*$", line)
        if m:
            state[m.group(1)] = m.group(2)
    return state


def get_sonic_ext_arc_nodes(duthost):
    """Return {vpp interface: set of sonic-ext-* feature nodes attached to it}."""
    names = []
    for line in vppctl(duthost, "show interface").splitlines():
        fields = line.split()
        if not fields or line[0].isspace() or fields[0] == "Name":
            continue
        if re.match(r"^[\w./:-]+$", fields[0]):
            names.append(fields[0])
    pytest_assert(names, "No VPP interfaces found")

    # One docker exec for all interfaces; one per interface is too slow on KVM.
    script = 'for i in {}; do echo "@@ $i"; vppctl show interface features $i; done'.format(" ".join(names))
    output = duthost.shell("docker exec syncd sh -c '{}'".format(script))["stdout"]

    nodes = {}
    current = None
    for line in output.splitlines():
        if line.startswith("@@ "):
            current = line[3:].strip()
            nodes[current] = set()
        elif current:
            nodes[current].update(re.findall(r"sonic-ext-[a-z0-9-]+", line))
    return nodes


def get_l2_classify_next_nodes(duthost):
    output = vppctl(duthost, "show vlib graph l2-input-classify")
    return set(re.findall(r"\b(linux-cp-punt|sonic-ext-[a-z0-9-]+)\b", output))


def count_lcp_pairs(duthost):
    return len(re.findall(r"^itf-pair:", vppctl(duthost, "show lcp"), re.MULTILINE))


def vpp_wired_arc_mismatches(duthost, expected):
    """Compare arc membership against what the VPP-wired toggles imply."""
    pvm = expected["punt-via-member"] == "on"
    dms = expected["drop-member-stats"] == "on"
    want = {
        # capture has no keyword: it produces the cookie the other two consume.
        "sonic-ext-capture": pvm or dms,
        "sonic-ext-host-xc": expected["host-xc"] == "on",
        "sonic-ext-drop-member-stats": dms,
        "sonic-ext-glean-redirect": pvm,
    }
    nodes = get_sonic_ext_arc_nodes(duthost)
    # aggr-tap-redirect only lands on the host tap of a bond, so only meaningful with one.
    if any(name.startswith("BondEthernet") for name in nodes):
        want["sonic-ext-aggr-tap-redirect"] = pvm

    attached = set().union(*nodes.values())
    return ["{} expected {}, got {}".format(node, "attached" if on else "absent",
                                            "attached" if node in attached else "absent")
            for node, on in want.items() if (node in attached) != on]


def verify_vpp_wired_arcs(duthost, expected):
    mismatches = []

    def _matches():
        mismatches[:] = vpp_wired_arc_mismatches(duthost, expected)
        return not mismatches

    pytest_assert(wait_until(ARC_WAIT_TIMEOUT, ARC_WAIT_INTERVAL, 0, _matches),
                  "sonic-ext feature arcs do not match {}:\n{}".format(expected, "\n".join(mismatches)))


def ip2me_attached_interfaces(duthost):
    return sorted(name for name, feats in get_sonic_ext_arc_nodes(duthost).items()
                  if any(f.startswith("sonic-ext-ip2me") for f in feats))


def add_ip2me_acl(duthost, port):
    duthost.shell("config acl add table {} L3 -s ingress -p {}".format(IP2ME_ACL_TABLE, port))
    duthost.shell('sonic-db-cli CONFIG_DB hset "ACL_RULE|{}|{}" PRIORITY 9999 PACKET_ACTION DROP SRC_IP {}'
                  .format(IP2ME_ACL_TABLE, IP2ME_ACL_RULE, IP2ME_ACL_SRC_IP))
    # syncd runs in sync mode, so Active means saivpp has already refreshed ip2me for the port.
    pytest_assert(wait_until(60, 5, 0, ip2me_acl_rule_active, duthost),
                  "ACL rule {}|{} did not become Active".format(IP2ME_ACL_TABLE, IP2ME_ACL_RULE))


def ip2me_acl_rule_active(duthost):
    output = duthost.shell("show acl rule {} {}".format(IP2ME_ACL_TABLE, IP2ME_ACL_RULE),
                           module_ignore_errors=True)["stdout"]
    return "Active" in output


def remove_ip2me_acl_rule(duthost):
    duthost.shell('sonic-db-cli CONFIG_DB del "ACL_RULE|{}|{}"'.format(IP2ME_ACL_TABLE, IP2ME_ACL_RULE),
                  module_ignore_errors=True)


def remove_ip2me_acl(duthost):
    remove_ip2me_acl_rule(duthost)
    duthost.shell("config acl remove table {}".format(IP2ME_ACL_TABLE), module_ignore_errors=True)


def reload_with_sonic_ext_config(setup, entries, wait_for_bgp):
    """Set SONIC_EXT_CONFIG and restart so vpp_init.sh renders it; None restores the defaults."""
    duthost = setup["duthost"]
    duthost.shell("sed -i '/^SONIC_EXT_CONFIG=/d' {}".format(SYNCD_VPP_ENV))
    if entries:
        value = ",".join("{}={}".format(k, v) for k, v in entries.items())
        duthost.shell("echo 'SONIC_EXT_CONFIG={}' >> {}".format(value, SYNCD_VPP_ENV))
    setup["reloaded"] = True
    # punt-via-member off breaks BGP over PortChannels, so the caller decides whether to wait for it.
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=wait_for_bgp)

    # Every port and PortChannel gets an LCP pair; until then "not attached" proves nothing.
    pytest_assert(wait_until(ARC_WAIT_TIMEOUT, ARC_WAIT_INTERVAL, 0,
                             lambda: count_lcp_pairs(duthost) >= setup["min_lcp_pairs"]),
                  "LCP pairs were not created after reload")


def verify_state(duthost, expected):
    state = get_sonic_ext_state(duthost)
    for feature, value in expected.items():
        pytest_assert(state.get(feature) == value,
                      "'show sonic-ext' reports {}={}, expected {}".format(feature, state.get(feature), value))


@pytest.fixture(scope="module")
def sonic_ext_setup(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    pytest_require(duthost.stat(path=SYNCD_VPP_ENV)["stat"]["exists"],
                   "{} not found".format(SYNCD_VPP_ENV))
    state = get_sonic_ext_state(duthost)
    pytest_require(all(feature in state for feature in DEFAULT_STATE),
                   "Image predates sonic-ext feature selection: {}".format(state))

    saivpp_supported = duthost.shell(
        "docker exec syncd sh -c \"grep -l 'disabled in startup.conf' /usr/lib/*/libsaivs.so* 2>/dev/null\"",
        module_ignore_errors=True)["rc"] == 0

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    portchannels = list(mg_facts["minigraph_portchannels"].keys())
    ports = list(mg_facts["minigraph_ports"].keys())
    pytest_require(portchannels or ports, "No port to bind the ip2me test ACL to")

    setup = {
        "duthost": duthost,
        "is_t0": tbinfo["topo"]["type"] == "t0",
        "saivpp_supported": saivpp_supported,
        "acl_port": portchannels[0] if portchannels else ports[0],
        "min_lcp_pairs": len(ports) + len(portchannels),
        "reloaded": False,
    }

    duthost.shell("cp -p {} {}".format(SYNCD_VPP_ENV, SYNCD_VPP_ENV_BACKUP))
    has_override = duthost.shell("grep -q '^SONIC_EXT_CONFIG=' {}".format(SYNCD_VPP_ENV),
                                 module_ignore_errors=True)["rc"] == 0
    try:
        if has_override:
            logger.info("Clearing the existing SONIC_EXT_CONFIG so the tests start from the defaults")
            reload_with_sonic_ext_config(setup, None, wait_for_bgp=True)
        yield setup
    finally:
        remove_ip2me_acl(duthost)
        duthost.shell("mv -f {} {}".format(SYNCD_VPP_ENV_BACKUP, SYNCD_VPP_ENV))
        if setup["reloaded"]:
            logger.info("Restoring the original sonic-ext configuration")
            config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)


@pytest.fixture
def ip2me_acl_cleanup(sonic_ext_setup):
    yield
    remove_ip2me_acl(sonic_ext_setup["duthost"])


def test_sonic_ext_default_state(sonic_ext_setup, ip2me_acl_cleanup):
    """
    With no SONIC_EXT_CONFIG every feature is on and wired, and ip2me follows ACL changes at runtime.
    Also the baseline that makes the "off" cases meaningful: each check here is inverted there.
    """
    duthost = sonic_ext_setup["duthost"]
    state = get_sonic_ext_state(duthost)
    pytest_require(all(state[f] == "on" for f in DEFAULT_STATE),
                   "DUT is not in the default all-on sonic-ext state: {}".format(state))

    verify_state(duthost, {"capture (derived)": "on"})
    verify_vpp_wired_arcs(duthost, DEFAULT_STATE)

    if sonic_ext_setup["is_t0"]:
        next_nodes = get_l2_classify_next_nodes(duthost)
        for node in ("linux-cp-punt", "sonic-ext-l2-trap-fixup", "sonic-ext-l2-vlan-filter"):
            pytest_assert(node in next_nodes,
                          "{} missing from l2-input-classify next nodes: {}".format(node, sorted(next_nodes)))

    add_ip2me_acl(duthost, sonic_ext_setup["acl_port"])
    pytest_assert(wait_until(60, 5, 0, lambda: bool(ip2me_attached_interfaces(duthost))),
                  "ip2me not attached after binding a deny ACL to {}".format(sonic_ext_setup["acl_port"]))

    remove_ip2me_acl_rule(duthost)
    pytest_assert(wait_until(60, 5, 0, lambda: not ip2me_attached_interfaces(duthost)),
                  "ip2me still attached after removing the deny rule: {}".format(ip2me_attached_interfaces(duthost)))


@pytest.mark.parametrize("entries", [
    pytest.param({"punt-via-member": "off", "host-xc": "off", "drop-member-stats": "off"}, id="all-off"),
    pytest.param({"punt-via-member": "off", "drop-member-stats": "on"}, id="capture-derived"),
])
def test_sonic_ext_vpp_wired_features_off(sonic_ext_setup, entries):
    """
    A boot-time "off" leaves the node off its feature arc entirely, and capture follows its two consumers.
    """
    duthost = sonic_ext_setup["duthost"]
    expected = dict(DEFAULT_STATE, **entries)

    reload_with_sonic_ext_config(sonic_ext_setup, entries, wait_for_bgp=False)

    capture = "on" if "on" in (expected["punt-via-member"], expected["drop-member-stats"]) else "off"
    verify_state(duthost, dict(expected, **{"capture (derived)": capture}))
    verify_vpp_wired_arcs(duthost, expected)


def test_sonic_ext_saivpp_wired_features_off(sonic_ext_setup, ip2me_acl_cleanup):
    """
    saivpp asks VPP, logs that it skipped each feature, and never wires it.
    """
    pytest_require(sonic_ext_setup["saivpp_supported"], "saivpp does not query sonic_ext_feature_get")
    duthost = sonic_ext_setup["duthost"]
    entries = {feature: "off" for feature in SAIVPP_WIRED}

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="sonic_ext_saivpp_wired_off")
    # The l2 features are only queried once a VLAN member exists, which t1 topologies do not have.
    queried = SAIVPP_WIRED if sonic_ext_setup["is_t0"] else ("ip2me",)
    loganalyzer.expect_regex = [SAIVPP_DISABLED_NOTICE_RE.format(f) for f in queried]
    loganalyzer.match_regex = [SAIVPP_QUERY_FAILED_RE]

    with loganalyzer:
        with DisableLogrotateAndWaitSyslogContext(duthost):
            reload_with_sonic_ext_config(sonic_ext_setup, entries, wait_for_bgp=True)
            add_ip2me_acl(duthost, sonic_ext_setup["acl_port"])

    verify_state(duthost, dict(DEFAULT_STATE, **entries))
    verify_vpp_wired_arcs(duthost, DEFAULT_STATE)

    attached = ip2me_attached_interfaces(duthost)
    pytest_assert(not attached, "ip2me attached despite ip2me off: {}".format(attached))

    if sonic_ext_setup["is_t0"]:
        # linux-cp-punt is added unconditionally first, so it proves the l2 punt init ran.
        pytest_assert(wait_until(ARC_WAIT_TIMEOUT, ARC_WAIT_INTERVAL, 0,
                                 lambda: "linux-cp-punt" in get_l2_classify_next_nodes(duthost)),
                      "l2 punt classify init never ran")
        next_nodes = get_l2_classify_next_nodes(duthost)
        wired = sorted(n for n in next_nodes if n.startswith("sonic-ext-"))
        pytest_assert(not wired, "sonic-ext nodes still wired into l2-input-classify: {}".format(wired))

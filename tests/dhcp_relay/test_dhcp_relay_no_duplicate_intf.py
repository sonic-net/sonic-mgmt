"""Regression test: rendered dhcp_relay supervisord.conf must never list the
same interface twice as an argument (-iu/-id/-im) to dhcrelay or dhcpmon.

Background
----------
Both the upstream ISC ``dhcrelay`` (in ``isc-dhcp-relay``) and the SONiC
``dhcpmon`` daemon accept multiple ``-iu``/``-id``/``-im`` arguments. Neither
deduplicates them:

* ``dhcrelay``: ``interface_snorf()`` in ``common/discover.c`` does not check
  for duplicates. ``discover_interfaces(DISCOVER_RELAY)`` then opens an
  ``if_register_receive`` + ``if_register_send`` pair per list entry, so two
  ``-iu Vlan1000`` flags result in two AF_PACKET sockets bound to the same
  interface and every received DHCP packet being forwarded twice.
* ``dhcpmon``: each duplicate ``-i*`` increments
  ``dhcp_num_north_intf``/``dhcp_num_south_intf``/``dhcp_num_mgmt_intf`` and
  ends up overwriting (and leaking) the previous ``intfs[name]`` device
  context. A duplicate ``-id``/``-im`` trips ``assert(... <= 1)`` and aborts
  the daemon (in debug builds).

Both behaviours are silent in the standard t0 testbed because every Vlan has
exactly one v4 prefix. They show up immediately when a Vlan has two v4
prefixes (the secondary-subnets configuration shipped as a
``sonic-config-engine`` fixture), or when the templates are widened to
``v4 OR v6`` so a dual-stack Vlan/PortChannel matches twice.

This test renders the production ``docker-dhcp-relay.supervisord.conf.j2``
template with a synthetic configuration that contains exactly such a
multi-prefix Vlan, parses every ``command=`` line, and asserts that no
single program has the same interface name listed twice with the same flag.

Companion fixes:
  * sonic-net/sonic-buildimage#27277 - template-side dedup (the fix this
    test gates).
  * sonic-net/sonic-dhcpmon - defensive dedup in ``dhcp_devman_add_intf``.
"""
import json
import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]

DHCP_RELAY_TEMPLATE_DIR_IN_CONTAINER = "/usr/share/sonic/templates"
TEMPLATE_BASENAME = "docker-dhcp-relay.supervisord.conf.j2"

# Flags whose argument is an interface name. Programs in the rendered
# supervisord.conf must list any given interface at most once per flag.
INTF_FLAGS = ("-iu", "-id", "-im", "-i")

# Synthetic CONFIG_DB used to drive the template render. The template's
# pfx_filter iterates per (name, prefix) so a Vlan with two v4 prefixes is
# what triggers the duplicate -iu emission for *other* relay programs.
SYNTHETIC_CONFIG = {
    "DEVICE_METADATA": {
        "localhost": {
            "hostname": "synth-dut",
            "platform": "x86_64-kvm_x86_64-r0",
            "type": "ToRRouter",
            "deployment_id": "1",
        }
    },
    "VLAN": {
        "Vlan1000": {
            "vlanid": "1000",
            "dhcp_servers": ["10.0.0.1", "10.0.0.2"],
        },
        "Vlan2000": {
            "vlanid": "2000",
            "dhcp_servers": ["10.0.0.1"],
        },
    },
    "VLAN_INTERFACE": {
        "Vlan1000": {},
        "Vlan1000|192.168.0.1/21": {},
        "Vlan1000|10.99.0.1/24": {},
        "Vlan1000|fc02:1000::1/64": {},
        "Vlan2000": {},
        "Vlan2000|192.168.16.1/21": {},
    },
    "PORTCHANNEL_INTERFACE": {
        "PortChannel0001": {},
        "PortChannel0001|10.0.0.56/31": {},
        "PortChannel0001|fc00::71/126": {},
    },
    "DHCP_RELAY": {
        "Vlan1000": {"dhcpv6_servers": ["fc02:2000::1"]},
        "Vlan2000": {"dhcpv6_servers": []},
    },
    "MGMT_INTERFACE": {
        "eth0": {},
        "eth0|10.250.0.10/24": {},
    },
}


def _copy_templates_to_host(duthost, dest_dir):
    """Copy the dhcp-relay jinja templates from the dhcp_relay container to
    the DUT host so ``sonic-cfggen`` (which lives on the host) can render
    them with the synthetic CONFIG_DB."""
    duthost.shell("mkdir -p {}".format(dest_dir))
    list_out = duthost.shell(
        "docker exec dhcp_relay sh -c "
        "'ls {}/*.j2 2>/dev/null'".format(DHCP_RELAY_TEMPLATE_DIR_IN_CONTAINER)
    )["stdout"].splitlines()
    pytest_assert(list_out, "no .j2 templates found in dhcp_relay container")
    for template_path in list_out:
        basename = template_path.rsplit("/", 1)[-1]
        duthost.shell(
            "docker exec dhcp_relay cat {src} > {dst}/{name}".format(
                src=template_path, dst=dest_dir, name=basename
            )
        )
    return "{}/{}".format(dest_dir, TEMPLATE_BASENAME)


def _render_template(duthost, template_path, config_path):
    return duthost.shell(
        "sonic-cfggen -j {cfg} -t {tpl}".format(cfg=config_path, tpl=template_path)
    )["stdout"]


def _extract_command_lines(rendered):
    """Return list of (program_name, command_line) tuples parsed out of the
    rendered supervisord.conf."""
    program_re = re.compile(r"^\[program:(?P<name>[^\]]+)\]\s*$")
    cmd_re = re.compile(r"^command=(?P<cmd>.*)$")
    pairs = []
    current = None
    for line in rendered.splitlines():
        m = program_re.match(line)
        if m:
            current = m.group("name")
            continue
        if current is None:
            continue
        m = cmd_re.match(line)
        if m:
            pairs.append((current, m.group("cmd").strip()))
            current = None
    return pairs


def _find_duplicate_intf_args(command_line):
    """Return a list of (flag, ifname, count) tuples for any (-iu/-id/-im)
    interface argument that appears more than once on the same command."""
    tokens = command_line.split()
    counts = {}  # (flag, ifname) -> count
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in INTF_FLAGS and i + 1 < len(tokens):
            ifname = tokens[i + 1]
            key = (token, ifname)
            counts[key] = counts.get(key, 0) + 1
            i += 2
            continue
        i += 1
    return [(flag, ifname, n) for (flag, ifname), n in counts.items() if n > 1]


def test_dhcp_relay_template_no_duplicate_intf_args(duthost):
    """Render docker-dhcp-relay.supervisord.conf.j2 with a synthetic config
    that contains a Vlan with two v4 prefixes. Assert that no rendered
    program lists the same interface twice with the same -i*/iu/id/im flag.

    This is the runtime equivalent of the secondary-subnets fixture check in
    sonic-config-engine: it exercises ``pfx_filter`` against a multi-prefix
    Vlan and proves that the supervisord template must dedup before passing
    interface names to dhcrelay/dhcpmon."""
    work_dir = "/tmp/dhcp_relay_dup_intf_test"
    duthost.shell("rm -rf {0} && mkdir -p {0}".format(work_dir))
    try:
        template_path = _copy_templates_to_host(duthost, work_dir)
        config_path = "{}/synth_config_db.json".format(work_dir)
        duthost.copy(content=json.dumps(SYNTHETIC_CONFIG), dest=config_path)

        rendered = _render_template(duthost, template_path, config_path)
        logger.info("rendered supervisord.conf:\n%s", rendered)

        commands = _extract_command_lines(rendered)
        pytest_assert(
            commands,
            "no [program:*] / command= pairs were rendered; template render likely failed",
        )

        all_dupes = []
        for program, cmd in commands:
            dupes = _find_duplicate_intf_args(cmd)
            for flag, ifname, count in dupes:
                all_dupes.append((program, flag, ifname, count, cmd))

        if all_dupes:
            logger.error("Rendered programs with duplicate -i* arguments:")
            for program, flag, ifname, count, cmd in all_dupes:
                logger.error(
                    "  [program:%s] %s %s appears %d times -> %s",
                    program, flag, ifname, count, cmd,
                )

        pytest_assert(
            not all_dupes,
            "Rendered dhcp_relay supervisord.conf passes the same interface "
            "name to dhcrelay/dhcpmon more than once via {flags}. ISC dhcrelay "
            "binds two AF_PACKET sockets per duplicate -iu (silent double "
            "forward) and dhcpmon overwrites/leaks the per-interface device "
            "context (and asserts on duplicate -id/-im). Offenders: {dupes}. "
            "Fix the template to dedup interface names before emitting "
            "command= -- see sonic-net/sonic-buildimage#27277.".format(
                flags=", ".join(INTF_FLAGS),
                dupes=[(p, f, i, n) for p, f, i, n, _ in all_dupes],
            ),
        )
    finally:
        duthost.shell("rm -rf {}".format(work_dir), module_ignore_errors=True)


def test_dhcp_relay_running_supervisord_no_duplicate_intf_args(duthost):
    """Sanity check on the actually-rendered, currently-deployed
    supervisord.conf inside the dhcp_relay container. On the standard t0/m0
    minigraph (one v4 prefix per Vlan) this passes; it would fail on a
    minigraph with secondary v4 subnets, or after the template is widened to
    cover dual-stack interfaces without dedup."""
    rendered = duthost.shell(
        "docker exec dhcp_relay cat /etc/supervisor/conf.d/"
        "docker-dhcp-relay.supervisord.conf"
    )["stdout"]
    commands = _extract_command_lines(rendered)
    pytest_assert(
        commands,
        "no [program:*] entries found in dhcp_relay container's "
        "supervisord.conf -- container missing or template render failed",
    )

    all_dupes = []
    for program, cmd in commands:
        dupes = _find_duplicate_intf_args(cmd)
        for flag, ifname, count in dupes:
            all_dupes.append((program, flag, ifname, count, cmd))

    if all_dupes:
        for program, flag, ifname, count, cmd in all_dupes:
            logger.error(
                "[program:%s] %s %s x%d in: %s", program, flag, ifname, count, cmd
            )

    pytest_assert(
        not all_dupes,
        "Running dhcp_relay supervisord.conf has duplicate -i* arguments: "
        "{}".format([(p, f, i, n) for p, f, i, n, _ in all_dupes]),
    )

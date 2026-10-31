"""
DUT side MACsec configuration helpers for the snappi MACsec tests (--snappi_macsec).

The MACsec profile is shared by all the ingress ports of a DUT, and a profile cannot be deleted while a port is
bound to it. Instead of deleting and re-creating the profile for every port, the profile configured on the DUT is
compared with the one required by the test:
    - profile absent: it is created by the test, and deleted during cleanup.
    - profile present with the same configuration: it is re-used, and left as is during cleanup.
    - profile present with a different configuration: the test is skipped before anything is configured.
A port that is bound to a different profile is unbound, and re-bound to its original profile during cleanup.
"""
import ast
import json
import logging
import os
import pytest

from tests.common.macsec.macsec_config_helper import set_macsec_profile, enable_macsec_port, disable_macsec_port, \
    delete_macsec_profile
from tests.common.macsec.macsec_helper import getns_prefix

logger = logging.getLogger(__name__)

MACSEC_PROFILE_NAME = '256_XPN_SCI'
MACSEC_PROFILE_FILE = "../tests/snappi_tests/macsec_profile.json"

# Profile attributes (keys of macsec_profile.json entries) that are compared with the DUT configuration.
MACSEC_PROFILE_ATTRS = ('priority', 'cipher_suite', 'primary_cak', 'primary_ckn', 'policy', 'send_sci',
                        'rekey_period')
# Optional profile attributes, compared only when specified in macsec_profile.json.
MACSEC_PROFILE_OPTIONAL_ATTRS = ('replay_protect', 'replay_window')
# Profile attributes whose name in CONFIG_DB MACSEC_PROFILE differs from the name in macsec_profile.json.
MACSEC_PROFILE_DB_ATTRS = {'replay_protect': 'enable_replay_protect'}
# Value assumed when the attribute is missing from the profile stored in CONFIG_DB.
MACSEC_PROFILE_ATTR_DEFAULTS = {'rekey_period': '0', 'replay_protect': 'false', 'replay_window': '0'}

# Ports on which this module enabled MACsec (to be disabled during cleanup).
macsec_enabled_ports = []
# (duthost, profile name) of the MACsec profiles created by this module (only these are deleted during cleanup).
macsec_created_profiles = []
# Ports that were bound to a different MACsec profile before the test and must be re-bound during cleanup.
macsec_rebind_ports = []


def load_macsec_profile_values():
    """Load the MACsec / snappi parameters from the macsec profile json file."""
    with open(os.path.expanduser(MACSEC_PROFILE_FILE), "r") as f:
        return json.load(f)


def _get_desired_macsec_profile(all_values, profile_name):
    """Return the MACsec profile attributes (as in macsec_profile.json) that the test requires on the DUT."""
    values = all_values[profile_name]
    desired = {attr: values[attr] for attr in MACSEC_PROFILE_ATTRS}
    for attr in MACSEC_PROFILE_OPTIONAL_ATTRS:
        if values.get(attr) is not None:
            desired[attr] = values[attr]
    # The replay window has no meaning when replay protection is disabled
    if str(desired.get('replay_protect', '')).lower() != 'true':
        desired.pop('replay_window', None)
    return desired


def _get_macsec_namespaces(duthost):
    """Namespaces in which the MACsec profile is configured (None for single asic DUTs)."""
    if duthost.is_multi_asic:
        return list(duthost.get_asic_namespace_list())
    return [None]


def _read_macsec_profile(duthost, namespace, profile_name):
    """Read MACSEC_PROFILE|<profile_name> from CONFIG_DB. Returns an empty dict if it does not exist."""
    ns_opt = "-n {}".format(namespace) if namespace else ""
    cmd = "sonic-db-cli {} CONFIG_DB HGETALL 'MACSEC_PROFILE|{}'".format(ns_opt, profile_name)
    output = duthost.command(cmd)['stdout'].strip()
    if not output:
        return {}
    return ast.literal_eval(output)


def _macsec_profile_matches(existing, desired):
    """Compare only the attributes that we configure; extra attributes on the DUT are ignored."""
    for attr, value in desired.items():
        default = MACSEC_PROFILE_ATTR_DEFAULTS.get(attr, '')
        db_attr = MACSEC_PROFILE_DB_ATTRS.get(attr, attr)
        if str(existing.get(db_attr, default)).lower() != str(value).lower():
            return False
    return True


def _get_macsec_profile_state(duthost, profile_name, desired):
    """
    Compare MACsec profile configured on the DUT (in all namespaces) with the desired one.
    Returns:
        'absent'   - profile does not exist in any namespace
        'match'    - profile exists in all namespaces with the same configuration as desired
        'conflict' - profile exists with different configuration (or only in some of the namespaces)
    """
    states = []
    for namespace in _get_macsec_namespaces(duthost):
        existing = _read_macsec_profile(duthost, namespace, profile_name)
        if not existing:
            states.append('absent')
        elif _macsec_profile_matches(existing, desired):
            states.append('match')
        else:
            states.append('conflict')
    if all(state == 'absent' for state in states):
        return 'absent'
    if all(state == 'match' for state in states):
        return 'match'
    return 'conflict'


def _get_macsec_port_profile(duthost, port_name):
    """Return the name of the MACsec profile the port is bound to, or an empty string if none."""
    ns_prefix = getns_prefix(duthost, port_name)
    cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' 'macsec'".format(ns_prefix, port_name)
    return duthost.command(cmd)['stdout'].strip()


def validate_macsec_profiles(snappi_ports):
    """
    Read-only check, done before configuring anything: skip the test if any DUT carrying a MACsec port
    (port_id >= 1) already has a profile with the name we need but with a different configuration.
    This way, no DUT is left with partial MACsec configuration.
    """
    all_values = load_macsec_profile_values()
    desired = _get_desired_macsec_profile(all_values, MACSEC_PROFILE_NAME)
    checked_duthosts = set()
    conflicts = []
    for port in snappi_ports:
        if int(port['port_id']) < 1:
            continue
        duthost = port['duthost']
        if duthost.hostname in checked_duthosts:
            continue
        checked_duthosts.add(duthost.hostname)
        state = _get_macsec_profile_state(duthost, MACSEC_PROFILE_NAME, desired)
        logger.info('MACsec profile {} on {}: {}'.format(MACSEC_PROFILE_NAME, duthost.hostname, state))
        if state == 'conflict':
            conflicts.append(duthost.hostname)
    if conflicts:
        pytest.skip('MACsec profile {} with a different configuration already exists on {}'.
                    format(MACSEC_PROFILE_NAME, ', '.join(conflicts)))


def configure_macsec_on_port(port, profile_name, all_values):
    """
    Bind the DUT port to the MACsec profile, creating the profile if needed.
        - port already bound to the profile: nothing to do.
        - port bound to another profile: unbind it (remembered for cleanup), the other profile is left as is.
        - profile already present with the same configuration: reuse it.
        - profile absent: create it (remembered for cleanup, only the profiles we create are deleted).
    """
    duthost = port['duthost']
    peer_port = port['peer_port']
    desired = _get_desired_macsec_profile(all_values, profile_name)

    bound_profile = _get_macsec_port_profile(duthost, peer_port)
    if bound_profile == profile_name:
        logger.info('Port {} on {} is already bound to MACsec profile {}, nothing to configure'.
                    format(peer_port, duthost.hostname, profile_name))
        return

    profile_state = _get_macsec_profile_state(duthost, profile_name, desired)
    # Should have been caught by validate_macsec_profiles, nothing has been changed for this port yet.
    if profile_state == 'conflict':
        pytest.skip('MACsec profile {} with a different configuration already exists on {}'.
                    format(profile_name, duthost.hostname))

    if bound_profile:
        logger.info('Port {} on {} is bound to MACsec profile {}. Unbinding it, the profile is left as is.'.
                    format(peer_port, duthost.hostname, bound_profile))
        port['macsec_original_profile'] = bound_profile
        disable_macsec_port(duthost, peer_port)
        if all(p['duthost'].hostname != duthost.hostname or p['peer_port'] != peer_port
               for p in macsec_rebind_ports):
            macsec_rebind_ports.append(port)

    if profile_state == 'absent':
        logger.info('Creating MACsec profile {} on {}'.format(profile_name, duthost.hostname))
        set_macsec_profile(duthost, profile_name, desired['priority'], desired['cipher_suite'],
                           desired['primary_cak'], desired['primary_ckn'], desired['policy'],
                           desired['send_sci'], desired['rekey_period'],
                           replay_protect=desired.get('replay_protect'),
                           replay_window=desired.get('replay_window'))
        if all(dut.hostname != duthost.hostname or name != profile_name
               for dut, name in macsec_created_profiles):
            macsec_created_profiles.append((duthost, profile_name))
    else:
        logger.info('Re-using existing MACsec profile {} on {}'.format(profile_name, duthost.hostname))

    enable_macsec_port(duthost, peer_port, profile_name)
    if all(enabled_port['duthost'].hostname != duthost.hostname
           or enabled_port['peer_port'] != peer_port
           for enabled_port in macsec_enabled_ports):
        macsec_enabled_ports.append(port)


def cleanup_macsec_config():
    """
    Restore the DUT MACsec configuration:
        - disable MACsec on the ports enabled by this module.
        - re-bind the ports that were bound to another profile before the test.
        - delete only the MACsec profiles created by this module, any other profile is left as is.
    """
    global macsec_enabled_ports, macsec_created_profiles, macsec_rebind_ports

    for port in reversed(macsec_enabled_ports):
        logger.info('Disabling MACsec on {} port {}'.
                    format(port['duthost'].hostname, port['peer_port']))
        disable_macsec_port(port['duthost'], port['peer_port'])
    macsec_enabled_ports = []

    # Re-bind the ports that were bound to another profile before the test, so that the DUT config is
    # same as before the test.
    for port in reversed(macsec_rebind_ports):
        original_profile = port.pop('macsec_original_profile', None)
        if not original_profile:
            continue
        current_profile = _get_macsec_port_profile(port['duthost'], port['peer_port'])
        if current_profile:
            logger.warning('Port {} on {} is bound to MACsec profile {}, not restoring profile {}'.
                           format(port['peer_port'], port['duthost'].hostname, current_profile,
                                  original_profile))
            continue
        logger.info('Restoring MACsec profile {} on {} port {}'.
                    format(original_profile, port['duthost'].hostname, port['peer_port']))
        enable_macsec_port(port['duthost'], port['peer_port'], original_profile)
    macsec_rebind_ports = []

    for dut, profile_name in macsec_created_profiles:
        logger.info('Deleting macsec profile {} on {}'.format(profile_name, dut.hostname))
        delete_macsec_profile(dut, profile_name)
    macsec_created_profiles = []

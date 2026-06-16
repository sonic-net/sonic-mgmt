import ipaddress
import json
import logging
import re
import os

from tests.common.devices.base import AnsibleHostBase
from tests.common.errors import RunAnsibleModuleFail
from retry import retry

logger = logging.getLogger(__name__)


def _raise_err(msg):
    logger.error(msg)
    raise Exception(msg)


FEC_MAP = {
    'fc': 'fire-code',
    'rs': 'reed-solomon'
}


_INTF_TOKEN_RE = re.compile(r'(?<=\binterface\s)(\S+)|(?<=\binterfaces\s)(\S+)')


def _apply_intf_map(value, intf_map):
    """Translate interface tokens via ``intf_map`` (converged-peer aware).

    On converged (multi-VRF) topologies a single cEOS VM hosts every logical
    neighbor and the per-logical-neighbor interface name (e.g. ``Ethernet1``
    from minigraph) maps to a different physical interface on the shared VM
    (e.g. ``Ethernet4``). ``ceos_topo_converger`` records that mapping in
    ``intf_map`` (``{logical: converged}``).

    This rewrites ``interface <name>`` / ``interfaces <name>`` tokens inside
    ``value`` (string, dict with ``command`` key, or list of either) so test
    code can keep using the per-logical name from minigraph.  Returns ``value``
    untouched when ``intf_map`` is empty (stock topology) so behavior is
    byte-identical there.
    """
    if not intf_map or value is None:
        return value

    def _sub(match):
        name = match.group(1) or match.group(2)
        return intf_map.get(name, name)

    def _rewrite_one(item):
        if isinstance(item, str):
            return _INTF_TOKEN_RE.sub(_sub, item)
        if isinstance(item, dict) and isinstance(item.get('command'), str):
            new_item = dict(item)
            new_item['command'] = _INTF_TOKEN_RE.sub(_sub, item['command'])
            return new_item
        return item

    if isinstance(value, list):
        return [_rewrite_one(item) for item in value]
    return _rewrite_one(value)


def _vrf_scope_bgp_parents(parents, vrf, prime_asn):
    """Rewrite ``router bgp <asn>`` config parents to be VRF-scoped.

    On converged (multi-VRF) topologies a single cEOS VM hosts every logical
    neighbor as a VRF under one global ``router bgp <prime_asn>`` process.
    Legacy test code targets ``router bgp <asn>`` in the default VRF, which on
    such a VM lands in the wrong place. This rewrites those parents to
    ``router bgp <prime_asn>`` / ``vrf <vrf>`` so existing test code works
    unchanged.

    Returns ``parents`` untouched when no VRF scoping applies (vrf unset, no
    ``router bgp`` parent, or the parents are already VRF-scoped).
    """
    if not vrf or parents is None:
        return parents
    as_list = parents if isinstance(parents, list) else [parents]
    if any(str(p).strip().startswith('vrf ') for p in as_list):
        return parents
    rewritten = []
    changed = False
    for parent in as_list:
        if str(parent).strip().startswith('router bgp'):
            rewritten.append('router bgp {}'.format(prime_asn))
            rewritten.append('vrf {}'.format(vrf))
            changed = True
        else:
            rewritten.append(parent)
    return rewritten if changed else parents


_BASH_PREFIX_RE = re.compile(r'^(\s*)bash\s+')
_BASH_ALREADY_SCOPED_RE = re.compile(r'^\s*bash\s+(?:sudo\s+)?ip\s+netns\s+exec\b')


def _vrf_scope_bash_commands(commands, vrf):
    """Wrap ``bash <cmd>`` invocations with ``sudo ip netns exec ns-<vrf>``.

    On converged (multi-VRF) cEOS hosts BGP/data-plane routes live in the
    per-VRF Linux network namespace ``ns-<vrf>`` (Arista's standard mapping
    between EOS VRFs and Linux namespaces). A plain ``bash <cmd>`` invocation
    via the EOS CLI runs in the *default* namespace which on converged has
    no route to DUT data-plane IPs, so any network tool (snmpget, ping,
    curl, traceroute, ...) fails with "Network is unreachable".

    This rewrites ``bash <cmd>`` into
    ``bash sudo ip netns exec ns-<vrf> <cmd>`` so the tool runs in the VRF
    that carries the BGP-learned routes to the DUT. Native EOS CLI commands
    (no ``bash`` prefix) and already-namespaced commands are left untouched.
    Returns ``commands`` unchanged when no VRF is set (stock topology).
    """
    if not vrf or commands is None:
        return commands
    scope_prefix = 'bash sudo ip netns exec ns-{} '.format(vrf)

    def _rewrite_text(text):
        if not _BASH_PREFIX_RE.match(text):
            return text
        if _BASH_ALREADY_SCOPED_RE.match(text):
            return text
        return _BASH_PREFIX_RE.sub(scope_prefix, text, count=1)

    def _rewrite_one(item):
        if isinstance(item, str):
            return _rewrite_text(item)
        if isinstance(item, dict) and isinstance(item.get('command'), str):
            new_item = dict(item)
            new_item['command'] = _rewrite_text(item['command'])
            return new_item
        return item

    if isinstance(commands, list):
        return [_rewrite_one(c) for c in commands]
    return _rewrite_one(commands)


_SHOW_BGP_RE = re.compile(r'^\s*show\s+(?:ip|ipv6)\s+bgp\b', re.IGNORECASE)


def _vrf_scope_eos_reads(commands, vrf):
    """VRF-scope raw ``show ip|ipv6 bgp`` reads on converged hosts.

    Tests that read the BGP table with a plain
    ``run_command('show ip bgp ...')`` hit the prime's *default* VRF, which on
    a converged peer carries only the backplane -- the logical neighbor's
    learned/advertised routes live under its per-neighbor VRF (same rationale
    as ``get_route``). This injects ``vrf <vrf>`` into such reads, before any
    ``| <filter>`` pipe where EOS requires it (``show ip bgp ... vrf X`` is
    valid, ``show ip bgp vrf X ...`` is not).

    Only plain string commands are rewritten; the structured ``dict`` commands
    built by ``get_route``/``run_command_json`` are left untouched (``get_route``
    already scopes its own VRF). Commands that already carry an explicit
    ``vrf`` token, and non ``show ... bgp`` commands (e.g.
    ``show run | grep 'router bgp'``), are left untouched. Returns ``commands``
    unchanged when no VRF is set so stock topologies are byte-identical.
    """
    if not vrf or commands is None:
        return commands

    def _rewrite_text(text):
        if not _SHOW_BGP_RE.match(text):
            return text
        if re.search(r'\bvrf\b', text, re.IGNORECASE):
            return text
        if '|' in text:
            head, _, tail = text.partition('|')
            return '{} vrf {} |{}'.format(head.rstrip(), vrf, tail)
        return '{} vrf {}'.format(text.rstrip(), vrf)

    def _rewrite_one(item):
        if isinstance(item, str):
            return _rewrite_text(item)
        return item

    if isinstance(commands, list):
        return [_rewrite_one(c) for c in commands]
    return _rewrite_one(commands)


# Loopback IDs created ad-hoc by tests via the lowercase
# ``interface loopback <N>`` idiom collide with the converged prime's per-VRF
# ``Loopback<N>`` interfaces (each merged sub-peer owns a small-numbered
# Loopback for its router-id). EOS interface names are global, so a test
# creating ``loopback 10`` would otherwise steal ``Loopback10`` from another
# VRF. On converged hosts we shift the test's loopback id by this offset into
# an unused range (well above the per-VRF loopback space, which is bounded by
# the cEOS interface limit) and place it in the neighbor's VRF. Validated on
# the cEOS lab image (``Loopback1010`` accepted).
_CONVERGED_TEST_LOOPBACK_OFFSET = 1000

_ROUTER_BGP_RE = re.compile(r'^\s*router\s+bgp\s+\d+', re.IGNORECASE)
# Match only the lowercase ad-hoc idiom (``interface loopback <N>``); the
# converged prime's real interfaces render as capitalized ``Loopback<N>`` and
# must not be renumbered.
_TEST_LOOPBACK_RE = re.compile(r'^(\s*)interface\s+loopback\s+(\d+)\s*$')


def _vrf_scope_eos_config(commands, vrf, prime_asn):
    """VRF-scope ad-hoc BGP/loopback config pushed via ``run_command_list``.

    Some tests push config by feeding ``eos_command`` a ``configure``-prefixed
    list of native CLI lines (instead of ``eos_config``). On converged hosts
    that config must be VRF-scoped exactly like ``eos_config`` does:

    * ``router bgp <asn>`` -> ``router bgp <prime_asn>`` followed by
      ``vrf <vrf>`` so the nested ``address-family``/``network`` statements
      land in the neighbor's VRF rather than the prime's default process.
    * ``interface loopback <N>`` -> a collision-free
      ``Loopback<N + offset>`` (see ``_CONVERGED_TEST_LOOPBACK_OFFSET``)
      followed by ``vrf <vrf>``, so the connected host route used to source an
      advertised ``network`` exists in the right VRF instead of clobbering a
      sub-peer's Loopback.

    Returns ``commands`` unchanged when no VRF is set, the input is not a list,
    or nothing matches -- so stock topologies and ordinary command lists are
    byte-identical.
    """
    if not vrf or not isinstance(commands, list):
        return commands
    if not any(isinstance(c, str)
               and (_ROUTER_BGP_RE.match(c) or _TEST_LOOPBACK_RE.match(c))
               for c in commands):
        return commands
    rewritten = []
    for cmd in commands:
        if isinstance(cmd, str):
            loopback_match = _TEST_LOOPBACK_RE.match(cmd)
            if loopback_match:
                indent, num = loopback_match.group(1), int(loopback_match.group(2))
                rewritten.append('{}interface Loopback{}'.format(
                    indent, num + _CONVERGED_TEST_LOOPBACK_OFFSET))
                rewritten.append('vrf {}'.format(vrf))
                continue
            if _ROUTER_BGP_RE.match(cmd) and prime_asn:
                rewritten.append('router bgp {}'.format(prime_asn))
                rewritten.append('vrf {}'.format(vrf))
                continue
        rewritten.append(cmd)
    return rewritten


class EosHost(AnsibleHostBase):
    """
    @summary: Class for Eos switch

    For running ansible module on the Eos switch
    """

    def __init__(self, ansible_adhoc, hostname, eos_user, eos_passwd,
                 shell_user=None, shell_passwd=None, gather_facts=False):
        '''Initialize an object for interacting with EoS type device using ansible modules

        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the EOS device
            eos_user (string): Username for accessing the EOS CLI interface
            eos_passwd (string): Password for the eos_user
            shell_user (string, optional): Username for accessing the Linux shell CLI interface. Defaults to None.
            shell_passwd (string, optional): Password for the shell_user. Defaults to None.
            gather_facts (bool, optional): Whether to gather some basic facts. Defaults to False.
        '''
        self.eos_user = eos_user
        self.eos_passwd = eos_passwd
        self.shell_user = shell_user
        self.shell_passwd = shell_passwd
        self.is_multi_asic = False
        # VRF scoping for converged (multi-VRF) topologies. When set, BGP config
        # parents are transparently rewritten to be VRF-scoped in eos_config().
        # Left as None on stock topologies so behavior is byte-identical.
        self.bgp_vrf = None
        self.bgp_prime_asn = None
        # Interface-name translation for converged topologies. When set, any
        # ``interface <name>`` / ``interfaces <name>`` token in eos_config()
        # parents/lines and eos_command() commands is translated through this
        # ``{logical: converged}`` map so tests can keep using the per-logical
        # name reported by minigraph. Left as None on stock topologies.
        self.intf_map = None
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local',
                                       host_pattern="localhost")["localhost"]

    def __getattr__(self, module_name):
        if module_name.startswith('eos_'):
            evars = {
                'ansible_connection': 'network_cli',
                'ansible_network_os': 'eos',
                'ansible_user': self.eos_user,
                'ansible_password': self.eos_passwd,
                'ansible_ssh_user': self.eos_user,
                'ansible_ssh_pass': self.eos_passwd,
                'ansible_become_method': 'enable'
            }
        else:
            if not self.shell_user or not self.shell_passwd:
                raise Exception("Please specify shell_user and shell_passwd for {}".format(self.hostname))
            evars = {
                'ansible_connection': 'ssh',
                'ansible_network_os': 'linux',
                'ansible_user': self.shell_user,
                'ansible_password': self.shell_passwd,
                'ansible_ssh_user': self.shell_user,
                'ansible_ssh_pass': self.shell_passwd,
                'ansible_become_method': 'sudo'
            }
        self.host.options['variable_manager'].extra_vars.update(evars)
        return super(EosHost, self).__getattr__(module_name)

    def __str__(self):
        return '<EosHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()

    def eos_config(self, *args, **kwargs):
        """VRF-aware wrapper around the ``eos_config`` Ansible module.

        All EosHost config writes (config(), shutdown(), no_shutdown_bgp(),
        and direct test calls) funnel through here. On converged topologies
        BGP config parents are transparently VRF-scoped and per-logical
        interface names are translated to the converged VM's actual interface
        names; on stock topologies the call is passed through unchanged.
        """
        if self.intf_map:
            for key in ('parents', 'lines'):
                if key in kwargs:
                    kwargs[key] = _apply_intf_map(kwargs[key], self.intf_map)
        if 'parents' in kwargs:
            kwargs['parents'] = _vrf_scope_bgp_parents(
                kwargs['parents'], self.bgp_vrf, self.bgp_prime_asn)
        ansible_eos_config = self.__getattr__('eos_config')
        return ansible_eos_config(*args, **kwargs)

    def eos_command(self, *args, **kwargs):
        """Converged-peer-aware wrapper around the ``eos_command`` Ansible module.

        On converged topologies these transparent rewrites happen:

        * ``interface <name>`` / ``interfaces <name>`` tokens in ``commands``
          are translated through ``intf_map`` so tests can keep using the
          per-logical-neighbor name from minigraph.
        * ``bash <cmd>`` invocations are wrapped with
          ``bash sudo ip netns exec ns-<bgp_vrf> <cmd>`` so network tools
          (snmpget, ping, ...) execute in the VRF that holds the BGP routes
          to the DUT instead of the route-less default namespace.
        * raw ``show ip|ipv6 bgp ...`` reads are VRF-scoped (``vrf <bgp_vrf>``
          injected before any ``| <filter>`` pipe) so they read the logical
          neighbor's routes instead of the prime's default VRF.
        * ad-hoc ``router bgp``/``interface loopback`` config lines pushed
          through ``run_command_list`` are VRF-scoped and de-collided the same
          way ``eos_config`` scopes BGP config (see ``_vrf_scope_eos_config``).

        On stock topologies the call is passed through unchanged.
        """
        if self.intf_map and 'commands' in kwargs:
            kwargs['commands'] = _apply_intf_map(kwargs['commands'], self.intf_map)
        if self.bgp_vrf and 'commands' in kwargs:
            kwargs['commands'] = _vrf_scope_bash_commands(
                kwargs['commands'], self.bgp_vrf)
            kwargs['commands'] = _vrf_scope_eos_reads(
                kwargs['commands'], self.bgp_vrf)
            kwargs['commands'] = _vrf_scope_eos_config(
                kwargs['commands'], self.bgp_vrf, self.bgp_prime_asn)
        ansible_eos_command = self.__getattr__('eos_command')
        return ansible_eos_command(*args, **kwargs)

    @retry(RunAnsibleModuleFail, tries=3, delay=5)
    def shutdown(self, interface_name):
        out = self.eos_config(
            lines=['shutdown'],
            parents=['interface {}'.format(interface_name)])
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def shutdown_multiple(self, interfaces):
        intf_str = ','.join(interfaces)
        return self.shutdown(intf_str)

    @retry(RunAnsibleModuleFail, tries=3, delay=5)
    def no_shutdown(self, interface_name):
        out = self.eos_config(
            lines=['no shutdown'],
            parents=['interface {}'.format(interface_name)])
        logging.info('No shut interface [%s]' % interface_name)
        return out

    def no_shutdown_multiple(self, interfaces):
        intf_str = ','.join(interfaces)
        return self.no_shutdown(intf_str)

    def is_lldp_disabled(self):
        """
        Checks if LLDP is enabled by neighbors
        Returns True if disabled (i.e. neighbors absent)
        Returns False if enabled (i.e. found neighbors)
        """
        command = 'show lldp neighbors | json'
        output = self.eos_command(commands=[command])['stdout']
        logger.debug(f'lldp neighbors returned: {output}')
        # check for empty output -> ['']
        if output is None or (len(output) == 1 and len(output[0]) == 0):
            return True
        return False

    def check_intf_link_state(self, interface_name):
        """
        This function returns link oper status
            e.g. cable not connected:
                     Ethernet1/1 is down, line protocol is notpresent (notconnect)
                 link is admin down(cable not present):
                     Ethernet1/1 is administratively down, line protocol is notpresent (disabled)
                 link is admin down(cable present):
                     Ethernet2/1 is administratively down, line protocol is down (disabled)
                 link is admin up&oper up:
                     Ethernet2/1 is up, line protocol is up (connected)
                 link is admin up&oper down:
                     Ethernet2/1 is down, line protocol is down (notconnect)
        In conclusion:
            connected = admin up & oper up
            disabled  = admin down
            notconnect= admin up & oper down
        """
        show_int_result = self.eos_command(
            commands=['show interface %s | json' % interface_name])
        int_status = show_int_result['stdout'][0]['interfaces'][interface_name]['interfaceStatus']
        return int_status == 'connected'

    def links_status_down(self, ports):
        show_int_result = self.eos_command(commands=['show interface status'])
        for output_line in show_int_result['stdout_lines'][0]:
            """
            Note:
            (Pdb) output_line
            u'Et33/1     lc-1-Ethernet0            notconnect   1134     full   100G   100GBASE-CR4
            e.g.
            (Pdb) output_line.split(' ')[0]
            u'Et1/1'
            """
            output_port = output_line.split(' ')[0].replace('Et', 'Ethernet')
            # Only care about port that connect to current DUT
            if output_port in ports:
                if 'notconnect' in output_line:
                    logging.info("Interface {} is down on {}".format(output_port, self.hostname))
                    continue
                if 'connected' in output_line:
                    logging.info("Interface {} is up on {}".format(output_port, self.hostname))
                    return False
                else:
                    logging.info("Please check status for interface {} on {}".format(output_port, self.hostname))
                    return False
        return True

    def links_status_up(self, ports):
        show_int_result = self.eos_command(commands=['show interface status'])
        for output_line in show_int_result['stdout_lines'][0]:
            """
            Note:
            (Pdb) output_line
            u'Et33/1     lc-1-Ethernet0            notconnect   1134     full   100G   100GBASE-CR4
            e.g.
            (Pdb) output_line.split(' ')[0]
            u'Et1/1'
            """
            output_port = output_line.split(' ')[0].replace('Et', 'Ethernet')
            # Only care about port that connect to current DUT
            if output_port in ports:
                if 'connected' in output_line:
                    logging.info("Interface {} is up on {}".format(output_port, self.hostname))
                    continue
                if 'notconnect' in output_line:
                    logging.info("Interface {} is down on {}".format(output_port, self.hostname))
                    return False
                else:
                    logging.info("Please check status for interface {} on {}".format(output_port, self.hostname))
                    return False
        return True

    def set_interface_lacp_rate_mode(self, interface_name, mode):
        out = self.eos_config(
            lines=['lacp rate %s' % mode],
            parents='interface %s' % interface_name)

        # FIXME: out['failed'] will be False even when a command is deprecated, so we have to check out['changed']
        # However, if the lacp rate is already in expected state, out['changed'] will be False and treated as
        # error.
        if out['failed'] is True or out['changed'] is False:
            # new eos deprecate lacp rate and use lacp timer command
            out = self.eos_config(
                lines=['lacp timer %s' % mode],
                parents='interface %s' % interface_name)
            if out['changed'] is False:
                logging.warning("Unable to set interface [%s] lacp timer to [%s]" % (interface_name, mode))
                raise Exception("Unable to set interface [%s] lacp timer to [%s]" % (interface_name, mode))
            else:
                logging.info("Set interface [%s] lacp timer to [%s]" % (interface_name, mode))
        else:
            logging.info("Set interface [%s] lacp rate to [%s]" % (interface_name, mode))
        return out

    def is_multiagent(self):
        out = self.eos_command(commands=["show ip route summary | json"])
        model = out["stdout"][0]["protoModelStatus"]["operatingProtoModel"]
        return model == "multi-agent"

    def kill_bgpd(self):
        agent = 'Bgp' if self.is_multiagent() else 'Rib'
        out = self.eos_config(lines=['agent {} shutdown'.format(agent)])
        return out

    @retry(RunAnsibleModuleFail, tries=3, delay=5)
    def start_bgpd(self):
        agent = 'Bgp' if self.is_multiagent() else 'Rib'
        out = self.eos_config(lines=['no agent {} shutdown'.format(agent)])
        return out

    @retry(RunAnsibleModuleFail, tries=3, delay=5)
    def no_shutdown_bgp(self, asn):
        out = self.eos_config(
            lines=['no shut'],
            parents=['router bgp {}'.format(asn)])
        logging.info('No shut BGP [%s]' % asn)
        return out

    @retry(RunAnsibleModuleFail, tries=3, delay=5)
    def no_shutdown_bgp_neighbors(self, asn, neighbors=[]):
        if not neighbors:
            return

        out = self.eos_config(
            lines=['no neighbor {} shutdown'.format(neighbor) for neighbor in neighbors],
            parents=['router bgp {}'.format(asn)]
        )
        logging.info('No shut BGP neighbors: {}'.format(json.dumps(neighbors)))
        return out

    def check_bgp_session_state(self, neigh_ips, neigh_desc,
                                state="established", vrf="default"):
        """
        @summary: check if current bgp session equals to the target state

        @param neigh_ips: bgp neighbor IPs
        @param neigh_desc: bgp neighbor description
        @param state: target state
        """
        neigh_ips = [ip.lower() for ip in neigh_ips]
        neigh_ips_ok = []
        neigh_desc_ok = []
        neigh_desc_available = False

        out_v4 = self.eos_command(
            commands=['show ip bgp summary vrf {} | json'.format(vrf)])
        logging.info("ip bgp summary: {}".format(out_v4))

        out_v6 = self.eos_command(
            commands=['show ipv6 bgp summary vrf {} | json'.format(vrf)])
        logging.info("ipv6 bgp summary: {}".format(out_v6))

        # when bgpd is inactive, the bgp summary output: [{u'vrfs': {}, u'warnings': [u'BGP inactive']}]
        if 'BGP inactive' in out_v4['stdout'][0].get('warnings', '') \
                and 'BGP inactive' in out_v6['stdout'][0].get('warnings', ''):
            return False

        try:
            for k, v in list(out_v4['stdout'][0]['vrfs'][vrf]['peers'].items()):
                if v['peerState'].lower() == state.lower():
                    if k in neigh_ips:
                        neigh_ips_ok.append(k)
                    if 'description' in v:
                        neigh_desc_available = True
                        if v['description'] in neigh_desc:
                            neigh_desc_ok.append(v['description'])

            for k, v in list(out_v6['stdout'][0]['vrfs'][vrf]['peers'].items()):
                if v['peerState'].lower() == state.lower():
                    if k.lower() in neigh_ips:
                        neigh_ips_ok.append(k)
                    if 'description' in v:
                        neigh_desc_available = True
                        if v['description'] in neigh_desc:
                            neigh_desc_ok.append(v['description'])
        except KeyError:
            # ignore any KeyError due to unexpected BGP summary output
            pass

        logging.info("neigh_ips_ok={} neigh_desc_available={} neigh_desc_ok={}"
                     .format(str(neigh_ips_ok), str(neigh_desc_available), str(neigh_desc_ok)))
        if neigh_desc_available:
            if len(neigh_ips) == len(neigh_ips_ok) and len(neigh_desc) == len(neigh_desc_ok):
                return True
        else:
            if len(neigh_ips) == len(neigh_ips_ok):
                return True

        return False

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} \
                            -l {fanout_host} --extra-vars \'{extra_vars}\' -vvvvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
                                           fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["localhost"]["stdout"]))

    def get_route(self, prefix, vrf=None):
        cmd = 'show ip bgp' if ipaddress.ip_network(prefix.encode().decode()).version == 4 else 'show ipv6 bgp'
        cmd = '{} {}'.format(cmd, prefix)
        # In converged (multi-VRF) mode, routes for this logical neighbor
        # live under the per-neighbor VRF on the prime EOS peer (``self.bgp_vrf``).
        # When the caller passes no explicit ``vrf=``, auto-scope to
        # ``self.bgp_vrf`` and surface the returned ``vrfs/<bgp_vrf>`` entry
        # under ``vrfs/default`` so existing readers that hardcode 'default'
        # (e.g. tests/bgp/test_bgp_bbr.py, tests/filterleaf/filterleaf_helpers.py,
        # tests/vlan/test_vlan_ports_down.py) keep working. We alias rather
        # than rename so the original VRF key is still present for any caller
        # that iterates ``vrfs.keys()``. Callers that pass an explicit
        # ``vrf=`` (e.g. tests/bgp/bgp_helpers.py) get the response unmodified.
        # On stock topologies ``self.bgp_vrf`` is None and behavior is
        # byte-identical.
        effective_vrf = vrf
        alias_as_default = False
        if effective_vrf is None and self.bgp_vrf:
            effective_vrf = self.bgp_vrf
            alias_as_default = True
        if effective_vrf:
            cmd = '{} vrf {}'.format(cmd, effective_vrf)
        out = self.eos_command(commands=[{
            'command': cmd,
            'output': 'json'
        }])['stdout'][0]
        if alias_as_default and isinstance(out, dict) and isinstance(out.get('vrfs'), dict):
            vrfs = out['vrfs']
            if effective_vrf in vrfs:
                # Overwrite any existing 'default' entry: in converged mode the
                # actual default VRF on the prime carries the backplane
                # config, not this logical neighbor's routes, so legacy callers
                # expect the per-neighbor view here.
                vrfs['default'] = vrfs[effective_vrf]
        return out

    def run_command_json(self, cmd):
        return self.eos_command(commands=[{
            'command': '{}'.format(cmd),
            'output': 'json'
        }])['stdout'][0]

    def run_command(self, cmd):
        return self.eos_command(commands=[cmd])

    def run_command_list(self, cmd):
        return self.eos_command(commands=cmd)

    def get_auto_negotiation_mode(self, interface_name):
        output = self.eos_command(commands=[{
            'command': 'show interfaces %s status' % interface_name,
            'output': 'json'
        }], module_ignore_errors=True)
        if self._has_cli_cmd_failed(output):
            logger.info('Failed to get auto neg state for {}: {}'.format(interface_name, output['msg']))
            return None
        autoneg_enabled = output['stdout'][0]['interfaceStatuses'][interface_name]['autoNegotiateActive']
        return autoneg_enabled

    def get_version(self):
        return self.eos_command(commands=["show version"])

    def _reset_port_speed(self, interface_name):
        out = self.eos_config(
                lines=['default speed'],
                parents=['interface {}'.format(interface_name)])
        logger.debug('Reset port speed for %s: %s' % (interface_name, out))
        return not self._has_cli_cmd_failed(out)

    def set_auto_negotiation_mode(self, interface_name, enabled):
        if self.get_auto_negotiation_mode(interface_name) == enabled:
            return True

        if enabled:
            speed_to_advertise = self.get_supported_speeds(interface_name)[-1]
            speed_to_advertise = speed_to_advertise[:-3] + 'gfull'
            out = self.eos_config(
                lines=['speed auto %s' % speed_to_advertise],
                parents=['interface {}'.format(interface_name)])
            logger.debug('Set auto neg to {} for port {}: {}'.format(enabled, interface_name, out))
            return not self._has_cli_cmd_failed(out)
        return self._reset_port_speed(interface_name)

    def get_speed(self, interface_name):
        output = self.eos_command(commands=['show interfaces %s transceiver properties' % interface_name])
        found_txt = re.search(r'Operational Speed: (\S+)', output['stdout'][0])
        if found_txt is None:
            _raise_err('Not able to extract interface %s speed from output: %s' % (interface_name, output['stdout']))

        v = found_txt.groups()[0]
        return v[:-1] + '000'

    def _has_cli_cmd_failed(self, cmd_output_obj):
        err_out = False
        if 'stdout' in cmd_output_obj:
            stdout = cmd_output_obj['stdout']
            msg = stdout[-1] if type(stdout) == list else stdout
            err_out = 'Cannot advertise' in msg

        return ('failed' in cmd_output_obj and cmd_output_obj['failed']) or err_out

    def set_speed(self, interface_name, speed):

        if not speed:
            # other set_speed implementations advertise port speeds when speed=None
            # but in EOS autoneg activation and speeds advertisement is done via a single CLI cmd
            # so this branch left nop intentionally
            return True

        speed_mode = 'auto' if self.get_auto_negotiation_mode(interface_name) else 'forced'
        speed = speed[:-3] + 'gfull'

        out = self.host.eos_command(commands=[
            'conf',
            'interface %s' % interface_name,
            {
                'command': 'speed {} {}'.format(speed_mode, speed),
                'prompt': ['Do you wish to proceed with this command'],
                'answer': ['y']}
            ])[self.hostname]
        logger.debug('Set force speed for port {} : {}'.format(interface_name, out))
        return not self._has_cli_cmd_failed(out)

    def get_supported_speeds(self, interface_name):
        """Get supported speeds for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            list: A list of supported speed strings or None
        """
        commands = ['show interfaces {} capabilities'.format(interface_name),
                    'show interface {} hardware'.format(interface_name)]
        for command in commands:
            output = self.eos_command(commands=[command])
            # Ignore case as EOS 4.23 has format of "Speed/Duplex" whereas 4.25 is "Speed/duplex"
            found_txt = re.search("Speed/Duplex: (.+)", output['stdout'][0], flags=re.IGNORECASE)
            if found_txt is not None:
                break

        if found_txt is None:
            _raise_err('Failed to find port speeds list in output: %s' % output['stdout'])

        speed_list = found_txt.groups()[0]
        speed_list = speed_list.split(',')

        try:
            speed_list.remove('auto')
        except ValueError:
            # auto may not be in speed options for certain versions
            pass

        def extract_speed_only(v):
            return re.match(r'\d+', v.strip()).group() + '000'
        return list(map(extract_speed_only, speed_list))

    def get_dut_iface_mac(self, interface_name):
        """
        Gets the MAC address of specified interface.

        Returns:
            str: The MAC address of the specified interface, or None if it is not found.
        """
        try:
            command = 'show interfaces {} | json'.format(interface_name)
            output = self.eos_command(commands=[command])['stdout'][0]
            forwardingModel = output["interfaces"][interface_name]["forwardingModel"]
            if forwardingModel == "routed":
                self.eos_config(
                    lines=['switchport'],
                    parents=['interface {}'.format(interface_name)])
                output = self.eos_command(commands=[command])['stdout'][0]
                self.eos_config(
                    lines=['no switchport'],
                    parents=['interface {}'.format(interface_name)])
            mac = output["interfaces"][interface_name]["physicalAddress"]
            return mac
        except Exception as e:
            logger.error('Failed to get MAC address for interface "{}", exception: {}'.format(interface_name, repr(e)))
            return None

    def iface_macsec_ok(self, interface_name):
        """
        Check if macsec is functional on specified interface.

        Returns: True or False
        """
        try:
            command = 'show mac security interface {} | json'.format(interface_name)
            output = self.eos_command(commands=[command])['stdout'][0]
            if interface_name in output["interfaces"]:
                return output["interfaces"][interface_name]["controlledPort"]
            return False
        except Exception as e:
            logger.error('Failed to get macsec status for interface "{}", exception: {}'
                         .format(interface_name, repr(e)))
            return False

    def _append_port_fec(self, interface_name, mode):
        def _exec(cmd):
            self.host.eos_command(commands=[
                'conf',
                'interface %s' % interface_name,
                cmd
            ])

        if mode:
            _exec('error-correction encoding ' + FEC_MAP[mode])
        else:
            _exec('no error-correction encoding')

    def set_port_fec(self, interface_name, mode):
        # reset FEC
        self._append_port_fec(interface_name, None)

        if mode:
            self._append_port_fec(interface_name, mode)

    def rm_member_from_channel_grp(self, interface_name, channel_group):
        out = self.eos_config(
            lines=['no channel-group {} mode active'.format(channel_group)],
            parents=['interface {}'.format(interface_name)])
        logging.info('Remove interface {} from channel_group {}'.format(interface_name, channel_group))
        return out

    def add_member_to_channel_grp(self, interface_name, channel_group):
        out = self.eos_config(
            lines=['channel-group {} mode active'.format(channel_group)],
            parents=['interface {}'.format(interface_name)])
        logging.info('Add interface {} to channel_group {}'.format(interface_name, channel_group))
        return out

    def ping_dest(self, dest):
        """
        Check if ping to dest IP sucess or not

        Returns: True or False
        """
        try:
            command = 'ping {} repeat 5'.format(dest)
            output = self.eos_command(commands=[command])['stdout'][0]
            return ' 0% packet loss' in output
        except Exception as e:
            logger.error('command {} failed. exception: {}'.format(command, repr(e)))
        return False

    def get_portchannel_by_member(self, member_intf):
        try:
            command = 'show lacp interface {} | json'.format(member_intf)
            output = self.eos_command(commands=[command])['stdout'][0]
            for port in list(output['portChannels'].keys()):
                return port
        except Exception as e:
            logger.error('Failed to get PortChannel for member interface "{}", exception: {}'.format(
                        member_intf, repr(e)
                        ))
            return None

    def load_configuration(self, config_file, backup_file=None):
        if backup_file is None:
            out = self.eos_config(
                src=config_file,
                replace='config',
            )
        else:
            out = self.eos_config(
                src=config_file,
                replace='line',
                backup='yes',
                backup_options={
                    'filename': os.path.basename(backup_file),
                    'dir_path': os.path.dirname(backup_file),
                }
            )
        return not self._has_cli_cmd_failed(out)

    def no_isis_interface(self, isis_instance, interface):
        out = self.eos_config(
            lines=['no isis enable'],
            parents=['interface {}'.format(interface)])
        return not self._has_cli_cmd_failed(out)

    def set_isis_metric(self, interface, metric):
        out = self.eos_config(
            lines=['isis metric {}'.format(metric)],
            parents=['interface {}'.format(interface)])
        return not self._has_cli_cmd_failed(out)

    def no_isis_metric(self, interface):
        out = self.eos_config(
            lines=['no isis metric'],
            parents=['interface {}'.format(interface)])
        return not self._has_cli_cmd_failed(out)

    def set_interface_lacp_time_multiplier(self, interface_name, multiplier):
        out = self.eos_config(
            lines=['lacp timer multiplier %d' % multiplier],
            parents='interface %s' % interface_name)

        if out['failed'] is True or out['changed'] is False:
            logging.warning("Unable to set interface [%s] lacp timer multiplier to [%d]" % (interface_name, multiplier))
        else:
            logging.info("Set interface [%s] lacp timer to [%d]" % (interface_name, multiplier))
        return out

    def no_lacp_time_multiplier(self, interface_name):
        out = self.eos_config(
            lines=['no lacp timer multiplier'],
            parents=['interface {}'.format(interface_name)])
        logging.info('Reset lacp timer to default for interface [%s]' % interface_name)
        return out

    def config(self, lines=None, parents=None, module_ignore_errors=False):
        return self.eos_config(lines=lines, parents=parents)

"""
CsonicHost - A lightweight host class for cSONiC (docker-sonic-vs) neighbor containers.

Instead of SSH/Ansible, this class uses 'docker exec' on the VM host to run commands
inside the cSONiC container. This avoids the need for sshd, admin user, or mgmt IP
inside the container.
"""

import json
import logging
import os
import subprocess
import time

from tests.common.devices.base import NeighborDevice

logger = logging.getLogger(__name__)


class CsonicHost(NeighborDevice):
    """
    A neighbor host running as a cSONiC (docker-sonic-vs) Docker container.

    Provides a command/shell interface compatible with SonicHost/EosHost by
    executing commands via 'docker exec' on the VM host rather than SSH.
    """

    def __init__(self, container_name, vm_host_ip=None, vm_host_user=None):
        """
        Args:
            container_name: Docker container name (e.g., 'csonic_vms6-1_VM0100')
            vm_host_ip: IP of the host running the container (default: localhost)
            vm_host_user: SSH user for the VM host (only needed if remote)
        """
        self.container_name = container_name
        self.hostname = container_name
        self.vm_host_ip = vm_host_ip
        self.vm_host_user = vm_host_user
        self.is_local = vm_host_ip is None or vm_host_ip in ('localhost', '127.0.0.1')

    def __str__(self):
        return '<CsonicHost {}>'.format(self.container_name)

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        # CsonicHost is stored as the ['host'] value of a NeighborDevice and is
        # used interchangeably with EosHost/SonicHost, which are hashable plain
        # objects. CsonicHost inherits NeighborDevice(dict), which is unhashable,
        # so some tests (e.g. iface_loopback_action) that place neighbor hosts in
        # a set or use them as dict keys raise "unhashable type: 'CsonicHost'".
        # Identity is the container name, so hash/eq on that keep host objects
        # hashable and distinct without relying on dict contents.
        return hash(self.container_name)

    def __eq__(self, other):
        return isinstance(other, CsonicHost) and self.container_name == other.container_name

    def __ne__(self, other):
        return not self.__eq__(other)

    def _docker_exec(self, cmd, **kwargs):
        """Run a command inside the Docker container via docker exec."""
        docker_cmd = ['docker', 'exec', self.container_name, 'bash', '-c', cmd]

        if not self.is_local:
            ssh_prefix = ['ssh', '-o', 'StrictHostKeyChecking=no',
                          '-o', 'UserKnownHostsFile=/dev/null']
            if self.vm_host_user:
                ssh_prefix.extend(['-l', self.vm_host_user])
            ssh_prefix.append(self.vm_host_ip)
            # Wrap docker command for remote execution
            docker_cmd = ssh_prefix + [' '.join(
                "'{}'".format(c) if ' ' in c else c for c in docker_cmd
            )]

        logger.debug("CsonicHost [%s] executing: %s", self.container_name, cmd)

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=kwargs.get('timeout', 30)
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            rc = result.returncode

            response = {
                'stdout': stdout,
                'stdout_lines': stdout.split('\n') if stdout else [],
                'stderr': stderr,
                'stderr_lines': stderr.split('\n') if stderr else [],
                'rc': rc,
                'failed': rc != 0 and not kwargs.get('module_ignore_errors', False),
            }

            if rc != 0 and not kwargs.get('module_ignore_errors', False):
                logger.warning("CsonicHost [%s] command failed (rc=%d): %s\nstderr: %s",
                               self.container_name, rc, cmd, stderr)

            return response

        except subprocess.TimeoutExpired:
            logger.error("CsonicHost [%s] command timed out: %s", self.container_name, cmd)
            return {
                'stdout': '',
                'stdout_lines': [],
                'stderr': 'Command timed out',
                'stderr_lines': ['Command timed out'],
                'rc': -1,
                'failed': True,
            }

    def command(self, cmd, **kwargs):
        """Run a command (compatible with Ansible command module interface)."""
        return self._docker_exec(cmd, **kwargs)

    def shell(self, cmd, **kwargs):
        """Run a shell command (compatible with Ansible shell module interface)."""
        return self._docker_exec(cmd, **kwargs)

    def run_command(self, cmd, **kwargs):
        """Run a single command inside the container and return its result."""
        return self._docker_exec(cmd, **kwargs)

    def run_command_list(self, cmds, **kwargs):
        """Run a list of commands inside the container, returning a result per command."""
        return [self._docker_exec(cmd, **kwargs) for cmd in cmds]

    def shell_cmds(self, cmds=None, continue_on_fail=False, **kwargs):
        """Run a sequence of shell commands, one result per command.

        Mirrors the ``shell_cmds`` Ansible module (used against EosHost/SonicHost
        neighbors, e.g. ospf/conftest.py) so cSONiC neighbors accept the same
        call. Returns the module-compatible shape ``{'cmds': [...], 'results':
        [{'cmd','stdout','stderr','rc',...}], 'failed': bool}``. By default it
        stops at the first failing command (matching the module's
        ``continue_on_fail=False`` default) unless ``continue_on_fail`` is set.
        """
        cmds = cmds or []
        results = []
        failed = False
        for cmd in cmds:
            res = self._docker_exec(cmd, module_ignore_errors=True)
            if not isinstance(res, dict):
                res = {'rc': 1, 'stderr': str(res)}
            rc = res.get('rc', 0)
            results.append({
                'cmd': cmd,
                'stdout': res.get('stdout', ''),
                'stdout_lines': res.get('stdout_lines', []),
                'stderr': res.get('stderr', ''),
                'stderr_lines': res.get('stderr_lines', []),
                'rc': rc,
                'err_msg': res.get('stderr', '') if rc != 0 else '',
            })
            if rc != 0:
                failed = True
                if not continue_on_fail:
                    break
        return {'cmds': cmds, 'results': results, 'failed': failed}

    def shutdown(self, ifname):
        """Shut down an interface.

        Mirrors ``SonicHost.shutdown`` (``config interface shutdown``) rather
        than a raw ``ip link`` change, since a cSONiC neighbor IS SONiC:
        driving the port through the SONiC CLI updates CONFIG_DB and lets the
        orchestration (portchannel/BGP) react correctly, which
        ``ip link set ... down`` would bypass.
        """
        logger.info("CsonicHost [%s] shutting down %s", self.container_name, ifname)
        return self._docker_exec("config interface shutdown {}".format(ifname),
                                 module_ignore_errors=True)

    def no_shutdown(self, ifname):
        """Bring up an interface.

        Mirrors ``SonicHost.no_shutdown`` (``config interface startup``); see
        :meth:`shutdown` for why the SONiC CLI is used instead of ``ip link``.
        """
        logger.info("CsonicHost [%s] bringing up %s", self.container_name, ifname)
        return self._docker_exec("config interface startup {}".format(ifname),
                                 module_ignore_errors=True)

    def get_route(self, prefix):
        """Get route info from FRR."""
        result = self._docker_exec("vtysh -c 'show ip route {} json'".format(prefix))
        if result['rc'] == 0 and result['stdout']:
            try:
                return json.loads(result['stdout'])
            except json.JSONDecodeError:
                pass
        return {}

    def get_port_channel_status(self, pc_name=None):
        """Get PortChannel status."""
        if pc_name:
            result = self._docker_exec("teamdctl {} state dump".format(pc_name))
        else:
            result = self._docker_exec("show interfaces portchannel")
        if result['rc'] == 0 and result['stdout']:
            try:
                return json.loads(result['stdout'])
            except (json.JSONDecodeError, ValueError):
                return result['stdout']
        return {}

    def config(self, lines=None, parents=None, **kwargs):
        """
        Configure via vtysh (loose compatibility with EOS config style).
        Translates config lines to vtysh commands.

        Config-mode commands (e.g. ``router bgp``, ``bgp graceful-restart``)
        must run inside FRR's configuration mode; vtysh rejects them with
        ``% Unknown command`` when issued at the enable prompt. We therefore
        prepend ``configure terminal`` so ``parents`` and ``lines`` are applied
        in config context, matching how EosHost.config()/SonicHost config work.
        """
        if not lines:
            return {}
        cmds = ['configure terminal']
        if parents:
            for p in parents:
                cmds.append(p)
        for line in lines:
            cmds.append(line)

        vtysh_cmd = "vtysh"
        for c in cmds:
            vtysh_cmd += " -c '{}'".format(c)

        return self._docker_exec(vtysh_cmd, **kwargs)

    def kill_bgpd(self):
        """Stop the BGP daemon inside the cSONiC container.

        Mirrors SonicHost.kill_bgpd (supervisorctl stop bgpd) so GR tests can
        take the neighbor's bgpd down and bring it back.
        """
        return self._docker_exec("supervisorctl stop bgpd", module_ignore_errors=True)

    def start_bgpd(self):
        """Start the BGP daemon inside the cSONiC container.

        Mirrors SonicHost.start_bgpd: after starting bgpd, restart bgpcfgd so
        the CONFIG_DB-derived BGP configuration is re-applied to FRR (starting
        bgpd alone leaves FRR without the config bgpcfgd renders). Waits for
        bgpd to report RUNNING (bounded) before restarting bgpcfgd, and surfaces
        a non-zero bgpcfgd-restart rc so a failed config re-apply is not silent.
        """
        result = self._docker_exec("supervisorctl start bgpd", module_ignore_errors=True)
        if result.get('rc', 1) != 0:
            return result
        # Wait for bgpd to actually be RUNNING before restarting bgpcfgd, rather
        # than relying on timing luck.
        deadline = time.time() + 30
        while time.time() < deadline:
            status = self._docker_exec("supervisorctl status bgpd", module_ignore_errors=True)
            if 'RUNNING' in str(status.get('stdout', '')):
                break
            time.sleep(2)
        else:
            logger.warning("CsonicHost [%s] start_bgpd: bgpd did not reach RUNNING "
                           "within timeout; restarting bgpcfgd anyway", self.container_name)
        cfg = self._docker_exec("supervisorctl restart bgpcfgd", module_ignore_errors=True)
        if cfg.get('rc', 1) != 0:
            logger.warning("CsonicHost [%s] start_bgpd: bgpcfgd restart failed rc=%s stderr=%s",
                           self.container_name, cfg.get('rc'), cfg.get('stderr', ''))
        return result

    def _bgp_summary_peers(self, afi, vrf):
        """Return the FRR BGP summary peers dict for an address family.

        Runs ``show bgp vrf <vrf> <afi> summary json`` via vtysh and returns the
        per-neighbor ``peers`` mapping (keyed by neighbor IP). Returns an empty
        dict if BGP/FRR is not answering or the address family is absent.
        """
        cmd = "vtysh -c 'show bgp vrf {} {} summary json'".format(vrf, afi)
        result = self._docker_exec(cmd, module_ignore_errors=True)
        if result.get('rc') != 0 or not result.get('stdout'):
            return {}
        try:
            data = json.loads(result['stdout'])
        except (json.JSONDecodeError, ValueError):
            return {}
        # FRR nests the summary under an address-family key
        # ("ipv4Unicast"/"ipv6Unicast") rather than EOS's vrfs.<vrf>.peers.
        af_key = 'ipv4Unicast' if afi == 'ipv4' else 'ipv6Unicast'
        return data.get(af_key, {}).get('peers', {}) or {}

    def check_bgp_session_state(self, neigh_ips, neigh_desc=None,
                                state="established", vrf="default"):
        """Check whether the given BGP neighbors are in the target state.

        Mirrors ``EosHost.check_bgp_session_state`` so cSONiC neighbors can be
        used interchangeably by tests (e.g. bgp/test_bgp_gr_helper.py). State is
        read from FRR via vtysh JSON. FRR's summary does not populate a peer
        ``description`` field, so neighbor descriptions are matched only when
        FRR reports one; otherwise the check passes on IP/state alone.

        @param neigh_ips: list of BGP neighbor IPs to verify
        @param neigh_desc: optional list of expected neighbor descriptions
        @param state: target peer state (default "established")
        @param vrf: VRF name (default "default")
        @return: True if all neigh_ips are in the target state
        """
        neigh_ips = [ip.lower() for ip in neigh_ips]
        neigh_desc = neigh_desc or []
        neigh_ips_ok = []
        neigh_desc_ok = []
        neigh_desc_available = False

        peers = {}
        # Merge both address families. Distinct v4/v6 neighbor IPs make key
        # collisions unexpected, but use update() for both so we never silently
        # drop a v6 peer just because a same-string key appeared under v4.
        for afi in ('ipv4', 'ipv6'):
            for k, v in self._bgp_summary_peers(afi, vrf).items():
                peers[k.lower()] = v

        if not peers:
            # Empty here means either FRR/vtysh did not answer / JSON failed to
            # parse, or no peers are established yet. Under wait_until both look
            # the same, so log so a genuine FRR error is distinguishable from
            # slow convergence.
            logger.warning("CsonicHost [%s] check_bgp_session_state: no peers from "
                           "BGP summary (FRR not answering, parse failure, or none "
                           "established yet)", self.container_name)
            return False

        for k, v in list(peers.items()):
            peer_state = str(v.get('state', '')).lower()
            if peer_state == state.lower():
                if k.lower() in neigh_ips:
                    neigh_ips_ok.append(k.lower())
                desc = v.get('description')
                if desc:
                    neigh_desc_available = True
                    if desc in neigh_desc:
                        neigh_desc_ok.append(desc)

        logger.info("CsonicHost [%s] check_bgp_session_state: neigh_ips_ok=%s "
                    "neigh_desc_available=%s neigh_desc_ok=%s",
                    self.container_name, str(neigh_ips_ok),
                    str(neigh_desc_available), str(neigh_desc_ok))

        if neigh_desc_available and neigh_desc:
            return (len(set(neigh_ips)) == len(set(neigh_ips_ok))
                    and len(neigh_desc) == len(neigh_desc_ok))
        return len(set(neigh_ips)) == len(set(neigh_ips_ok))

    def _bgp_neighbors_json(self, afi):
        """Return FRR's ``show <afi> bgp neighbors json`` mapping (ip -> info)."""
        show = 'show ip bgp neighbors json' if afi == 'ipv4' \
            else 'show bgp ipv6 neighbors json'
        result = self._docker_exec("vtysh -c '{}'".format(show),
                                   module_ignore_errors=True)
        if result.get('rc') != 0 or not result.get('stdout'):
            return {}
        try:
            data = json.loads(result['stdout'])
        except (json.JSONDecodeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def minigraph_facts(self, host=None, **kwargs):
        """Synthesize minigraph-style BGP facts for this cSONiC neighbor.

        Mirrors the ``minigraph_facts`` Ansible module for the fields tests
        consume from a *neighbor* (e.g. ospf/conftest.py reads
        ``minigraph_bgp`` and matches ``name == duthost.hostname`` to recover the
        DUT's peer address/ASN as seen by this neighbor). A cSONiC neighbor has
        no minigraph XML, so we derive the peer list from FRR: each BGP peer
        yields ``name`` (FRR's advertised peer ``hostname``), ``addr`` (peer IP)
        and ``asn`` (peer ``remoteAs``). Peers whose hostname FRR reports as
        ``Unknown`` (e.g. exabgp route injectors) are still included with that
        name, so only real DUT-facing sessions match ``duthost.hostname``.

        @param host: accepted for signature parity with the Ansible module
                     (callers pass ``host=<hostname>``); unused here.
        @return: dict with a ``minigraph_bgp`` list of {name, addr, asn} entries.
        """
        bgp_sessions = []
        seen = set()
        for afi in ('ipv4', 'ipv6'):
            for ip, info in self._bgp_neighbors_json(afi).items():
                key = ip.lower() if isinstance(ip, str) else ip
                if not isinstance(info, dict) or key in seen:
                    continue
                seen.add(key)
                remote_as = info.get('remoteAs')
                try:
                    asn = int(remote_as) if remote_as is not None else None
                except (TypeError, ValueError):
                    logger.warning("CsonicHost [%s] minigraph_facts: could not parse "
                                   "remoteAs=%r for peer %s; setting asn=None",
                                   self.container_name, remote_as, ip)
                    asn = None
                bgp_sessions.append({
                    'name': info.get('hostname'),
                    'addr': ip,
                    'asn': asn,
                })
        return {'minigraph_bgp': sorted(bgp_sessions, key=lambda x: str(x['addr']))}

    def fetch(self, src=None, dest=None, **kwargs):
        """
        Copy a file out of the cSONiC container to the local controller, mimicking
        the Ansible ``fetch`` module closely enough for techsupport collection.

        For a local VM host this uses ``docker cp``; for a remote VM host the file
        is first copied to the host's /tmp via ``docker cp`` over SSH and then
        pulled back with ``scp``.
        """
        if not src or not dest:
            return {'failed': True, 'msg': 'fetch requires src and dest'}

        dest_dir = os.path.join(dest, self.container_name)
        os.makedirs(dest_dir, exist_ok=True)
        local_dest = os.path.join(dest_dir, os.path.basename(src))

        try:
            if self.is_local:
                cp_cmd = ['docker', 'cp',
                          '{}:{}'.format(self.container_name, src), local_dest]
                result = subprocess.run(cp_cmd, capture_output=True, text=True,
                                        timeout=kwargs.get('timeout', 120))
            else:
                remote_tmp = '/tmp/{}_{}'.format(self.container_name, os.path.basename(src))
                ssh_base = ['ssh', '-o', 'StrictHostKeyChecking=no',
                            '-o', 'UserKnownHostsFile=/dev/null']
                target = self.vm_host_ip
                if self.vm_host_user:
                    target = '{}@{}'.format(self.vm_host_user, self.vm_host_ip)
                subprocess.run(ssh_base + [target,
                               'docker cp {}:{} {}'.format(self.container_name, src, remote_tmp)],
                               capture_output=True, text=True, timeout=kwargs.get('timeout', 120))
                scp_base = ['scp', '-o', 'StrictHostKeyChecking=no',
                            '-o', 'UserKnownHostsFile=/dev/null',
                            '{}:{}'.format(target, remote_tmp), local_dest]
                result = subprocess.run(scp_base, capture_output=True, text=True,
                                        timeout=kwargs.get('timeout', 120))

            rc = result.returncode
            return {
                'failed': rc != 0,
                'rc': rc,
                'dest': local_dest,
                'stderr': result.stderr.strip(),
            }
        except subprocess.TimeoutExpired:
            logger.error("CsonicHost [%s] fetch timed out: %s", self.container_name, src)
            return {'failed': True, 'msg': 'fetch timed out', 'dest': local_dest}

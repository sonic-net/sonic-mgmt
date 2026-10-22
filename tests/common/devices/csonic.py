"""
CsonicHost - A lightweight host class for cSONiC (docker-sonic-vs) neighbor containers.

Instead of SSH/Ansible, this class uses 'docker exec' on the VM host to run commands
inside the cSONiC container. This avoids the need for sshd, admin user, or mgmt IP
inside the container.
"""

import ipaddress
import json
import logging
import os
import re
import shlex
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

    def __init__(self, container_name, vm_host_ip=None, vm_host_user=None,
                 lag_backend=None):
        """
        Args:
            container_name: Docker container name (e.g., 'csonic_vms6-1_VM0100')
            vm_host_ip: IP of the host running the container (default: localhost)
            vm_host_user: SSH user for the VM host (only needed if remote)
            lag_backend: cSONiC LAG implementation (teamd or userspace_ovs)
        """
        self.container_name = container_name
        self.hostname = container_name
        self.vm_host_ip = vm_host_ip
        self.vm_host_user = vm_host_user
        self.lag_backend = (
            lag_backend or
            os.getenv("SONIC_MGMT_CSONIC_LAG_BACKEND", "teamd"))
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
            # SSH passes the final argument through the remote user's shell.
            # Quote every docker argv element so pipes, quotes, and multiline
            # ``bash -c`` scripts stay inside the container command.
            remote_command = ' '.join(shlex.quote(c) for c in docker_cmd)
            docker_cmd = ssh_prefix + [remote_command]

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

        On the opt-in userspace OVS LAG backend teamd is stopped and the bond
        is built on the mapped kernel device (ethN), so the CONFIG_DB port
        alone does not stop LACP; additionally down the bond member.
        """
        logger.info("CsonicHost [%s] shutting down %s", self.container_name, ifname)
        result = self._docker_exec("config interface shutdown {}".format(ifname),
                                   module_ignore_errors=True)
        self._set_ovs_bond_member_link(ifname, "down")
        return result

    def no_shutdown(self, ifname):
        """Bring up an interface.

        Mirrors ``SonicHost.no_shutdown`` (``config interface startup``); see
        :meth:`shutdown` for why the SONiC CLI is used instead of ``ip link``
        and why the userspace OVS LAG bond member is toggled as well.
        """
        logger.info("CsonicHost [%s] bringing up %s", self.container_name, ifname)
        result = self._docker_exec("config interface startup {}".format(ifname),
                                   module_ignore_errors=True)
        self._set_ovs_bond_member_link(ifname, "up")
        return result

    def _kernel_interface_name(self, interface_name):
        """Map a runtime SONiC port to its injected kernel dataplane link."""
        if not re.fullmatch(r"Ethernet\d+", interface_name):
            return interface_name

        links = self._docker_exec("ls /sys/class/net/")
        if links.get("rc") != 0:
            return None
        link_names = (links.get("stdout_lines") or
                      links.get("stdout", "").splitlines())
        ethernet_ports = sorted(
            (name for name in link_names
             if re.fullmatch(r"Ethernet\d+", name)),
            key=lambda name: int(re.search(r"\d+", name).group(0)))
        kernel_ports = sorted(
            (name for name in link_names
             if re.fullmatch(r"eth[1-9]\d*", name)),
            key=lambda name: int(re.search(r"\d+", name).group(0)))
        if interface_name not in ethernet_ports:
            return None
        index = ethernet_ports.index(interface_name)
        return kernel_ports[index] if index < len(kernel_ports) else None

    def _ovs_bond_member(self, interface_name, bond):
        """Return the active OVS device for a logical PortChannel member.

        The ordinal SONiC-port mapping is duplicated from ``kernel_member()``
        in ansible/roles/sonic/files/csonic_ovs_lag.py, which ships into the
        container as an Ansible module and cannot be imported here; keep the
        two in sync. MACsec-enabled OVS bonds use macsec_ethN so decrypted
        traffic reaches the PortChannel, while ordinary bonds use ethN.
        """
        device = self._kernel_interface_name(interface_name)
        if not device or not re.fullmatch(r"eth[1-9]\d*", device):
            raise Exception(
                "Unable to map unsupported cSONiC LAG member [{}] to a kernel device "
                "of bond [{}]".format(interface_name, bond))
        candidates = (device, "macsec_{}".format(device))
        # ovs_portchannel() creates each PortChannel as its own bridge and puts the
        # members into a Port named '<PortChannel>-bond'.
        bridge = bond[:-len("-bond")]
        result = self._docker_exec("ovs-vsctl list-ifaces {}".format(bridge),
                                   module_ignore_errors=True)
        if result.get("rc") != 0:
            raise Exception(
                "Unable to list OVS bridge [{}] interfaces for bond [{}]: {}"
                .format(bridge, bond, result.get("stderr", "")))
        members = result.get("stdout_lines", [])
        active = [candidate for candidate in candidates if candidate in members]
        if len(active) != 1:
            raise Exception(
                "Interface [{}] maps to OVS devices [{}], but bond [{}] has {} "
                "matching members (members: {}); refusing to toggle only [{}] "
                "because that would leave the active bond member unchanged".format(
                    interface_name, ",".join(candidates), bond, len(active),
                    ",".join(members) or "none", interface_name))
        return active[0]

    def _ovs_bond_interfaces(self, bond):
        """Return a bond's interfaces from one consistent OVSDB read."""
        bridge = bond[:-len("-bond")]
        result = self._docker_exec(
            "ovs-vsctl list-ifaces {}".format(shlex.quote(bridge)),
            module_ignore_errors=True)
        if result.get("rc") != 0:
            raise Exception(
                "Unable to list OVS bridge interfaces for bond [{}]: {}"
                .format(bond, result.get("stderr", "")))
        interfaces = result.get("stdout_lines") or [
            line for line in result.get("stdout", "").splitlines() if line]
        if not interfaces:
            raise Exception("OVS bond [{}] has no interfaces".format(bond))
        return interfaces

    def set_ovs_macsec_member(self, interface_name, enabled, timeout=60):
        """Select the encrypted or plain device for a userspace-OVS LAG member.

        The OVS backend is created before MACsec starts and initially bonds ethN.
        Linux MACsec exposes decrypted/encrypted data through macsec_ethN while
        retaining ethN for MKA (EAPOL). Replace only this member in the existing
        OVS Port so LACP and L3 traffic traverse MACsec. Teamd-backed and
        non-PortChannel interfaces are unchanged.
        """
        mapper = getattr(self, "_interface_name", None)
        if callable(mapper):
            interface_name = mapper(interface_name)
        bond = self._lacp_bond_for_member(interface_name)
        if bond is None:
            return None

        lower_device = self._kernel_interface_name(interface_name)
        if not lower_device or not re.fullmatch(r"eth[1-9]\d*", lower_device):
            raise Exception(
                "Unable to map unsupported cSONiC LAG member [{}] for MACsec "
                "bond [{}]".format(interface_name, bond))
        macsec_device = "macsec_{}".format(lower_device)
        desired = macsec_device if enabled else lower_device

        deadline = time.time() + timeout
        while True:
            link = self._docker_exec(
                "ip link show dev {}".format(desired),
                module_ignore_errors=True)
            if link.get("rc") == 0:
                break
            if time.time() >= deadline:
                raise Exception(
                    "OVS MACsec bond member [{}] did not appear for interface "
                    "[{}] on bond [{}] within {}s: {}".format(
                        desired, interface_name, bond, timeout,
                        link.get("stderr", "")))
            time.sleep(1)

        link = self._docker_exec(
            "ip link set {} up".format(desired),
            module_ignore_errors=True)
        if link.get("rc") != 0:
            raise Exception(
                "Unable to bring OVS MACsec bond member [{}] up for bond [{}]: {}"
                .format(desired, bond, link.get("stderr", "")))

        current = self._ovs_bond_member(interface_name, bond)
        if current == desired:
            return None

        # Mutate only this member. Rewriting the complete interfaces column can
        # lose a concurrent swap of another member on the same PortChannel.
        # Add the replacement before removing the current member: OVS enforces
        # Port.interfaces' minimum cardinality on each operation, so removing
        # the sole member first is rejected even within one transaction.
        transaction = [
            "ovs-vsctl",
            "--", "--id=@current", "get", "Interface", current, "_uuid",
            "--", "--id=@desired", "create", "Interface",
            "name={}".format(desired),
            "--", "add", "Port", bond, "interfaces", "@desired",
            "--", "remove", "Port", bond, "interfaces", "@current",
        ]
        swap = self._docker_exec(" ".join(transaction))
        if swap.get("rc") != 0:
            raise Exception(
                "Unable to replace OVS bond [{}] member [{}] with [{}]: {}"
                .format(bond, current, desired, swap.get("stderr", "")))

        updated = self._ovs_bond_interfaces(bond)
        if desired not in updated or current in updated:
            raise Exception(
                "OVS bond [{}] member replacement did not converge: expected "
                "[{}], removed [{}], members [{}]".format(
                    bond, desired, current, ",".join(updated) or "none"))
        return swap

    def _set_ovs_bond_member_link(self, interface_name, state):
        """Bring the userspace OVS LAG bond member of interface_name up/down.

        No-op (returns None) on any other backend, so teamd-backed neighbors keep
        the SONiC-CLI-only behaviour.
        """
        bond = self._lacp_bond_for_member(interface_name)
        if bond is None:
            return None
        device = self._ovs_bond_member(interface_name, bond)
        logger.info("CsonicHost [%s] setting OVS bond [%s] member %s (%s) %s",
                    self.container_name, bond, device, interface_name, state)
        return self._docker_exec("ip link set {} {}".format(device, state))

    def get_route(self, prefix):
        """Get BGP route info for a prefix from FRR.

        Mirrors ``SonicHost.get_route``: returns the parsed
        ``show bgp ipv4|ipv6 unicast <prefix> json`` output, which has a
        ``paths`` list when the prefix is in the BGP table. Returns ``{}`` when
        the prefix is absent or the command/JSON fails.
        """
        afi = 'ipv6' if ipaddress.ip_network(prefix, strict=False).version == 6 else 'ipv4'
        result = self._docker_exec('vtysh -c "show bgp {} unicast {} json"'.format(afi, prefix),
                                   module_ignore_errors=True)
        if result.get('rc') != 0 or not result.get('stdout'):
            return {}
        try:
            data = json.loads(result['stdout'])
        except (json.JSONDecodeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def get_dut_iface_mac(self, interface_name):
        """Return the MAC of the SONiC-facing interface.

        APPL_DB MACsec tables are keyed by the SCI derived from this
        ``EthernetN`` device, even though software MACsec runs on a separate
        injected ``ethN`` device in cSONiC.
        """
        interface_name = (
            self._interface_name(interface_name)
            if hasattr(self, "_interface_name") else interface_name)
        try:
            result = self._docker_exec(
                "cat /sys/class/net/{}/address".format(
                    shlex.quote(interface_name)))
            if result.get("rc") == 0 and result.get("stdout"):
                return result["stdout"].strip()
        except Exception as error:
            logger.error(
                'Failed to get MAC address for interface "%s", exception: %r',
                interface_name, error)
        return None

    def _get_macsec_ifname(self, interface_name):
        """Map a SONiC-facing port to its Linux MACsec interface."""
        interface_name = (
            self._interface_name(interface_name)
            if hasattr(self, "_interface_name") else interface_name)
        if not re.fullmatch(r"Ethernet\d+", interface_name):
            return interface_name
        kernel_interface = self._kernel_interface_name(interface_name)
        return ("macsec_{}".format(kernel_interface)
                if kernel_interface is not None else None)

    def get_macsec_iface_mac(self, interface_name):
        """Return the MAC of the Linux MACsec interface carrying traffic."""
        try:
            interface_name = self._get_macsec_ifname(interface_name)
            if interface_name is None:
                return None
            result = self._docker_exec(
                "cat /sys/class/net/{}/address".format(
                    shlex.quote(interface_name)))
            if result.get("rc") == 0 and result.get("stdout"):
                return result["stdout"].strip()
        except Exception as error:
            logger.error(
                'Failed to get MAC address for interface "%s", exception: %r',
                interface_name, error)
        return None

    def get_macsec_iface_sci(self, interface_name):
        """Return the SCI configured on the active Linux MACsec interface.

        Linux permits a MACsec interface's configured SCI to differ from its
        device MAC address. The kernel MACsec record is therefore the
        authoritative source for cSONiC MKA validation.
        """
        try:
            interface_name = self._get_macsec_ifname(interface_name)
            if interface_name is None:
                return None
            result = self._docker_exec("ip -j macsec show")
            if result.get("rc") != 0 or not result.get("stdout"):
                return None
            for port in json.loads(result["stdout"]):
                if port.get("ifname") != interface_name:
                    continue
                sci = str(port.get("sci", "")).lower().removeprefix("0x")
                return sci if re.fullmatch(r"[0-9a-f]{16}", sci) else None
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            logger.error(
                'Failed to get MACsec SCI for interface "%s", exception: %r',
                interface_name, error)
        return None

    def iface_macsec_ok(self, interface_name):
        """Check whether MACsec is operational on an interface.

        cSONiC is SONiC running inside the neighbor container, so use the same
        STATE_DB readiness signal as ``SonicHost.iface_macsec_ok``. ``shell``
        already executes directly in that container; wrapping this command in
        another ``docker exec`` would incorrectly require Docker in cSONiC.
        """
        try:
            cmd = 'sonic-db-cli STATE_DB HGET "MACSEC_PORT_TABLE|{}" state'.format(interface_name)
            state = self.shell(cmd)['stdout'].strip()
            return state == 'ok'
        except Exception as e:
            logger.error('Failed to get macsec status for interface "{}", exception: {}'
                         .format(interface_name, repr(e)))
            return False

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

    def _lacp_bond_for_member(self, interface_name):
        """Return the OVS bond port of the PortChannel that has interface_name as a member.

        Only the userspace OVS LAG backend creates these bonds (``<PortChannel>-bond``);
        returns None when the member has no PortChannel or the bond does not exist.
        """
        if self.lag_backend != "userspace_ovs":
            return None

        result = self._docker_exec(
            "sonic-db-cli CONFIG_DB keys 'PORTCHANNEL_MEMBER|*|{}'".format(interface_name),
            module_ignore_errors=True)
        if result.get("rc") != 0:
            raise Exception(
                "Unable to query PortChannel membership for interface [{}]: {}"
                .format(interface_name, result.get("stderr", "")))
        keys = result.get("stdout_lines", [])
        if not keys:
            return None
        bond = "{}-bond".format(keys[0].split('|')[1])
        result = self._docker_exec("ovs-vsctl --if-exists get Port {} name".format(bond),
                                   module_ignore_errors=True)
        if result.get("rc") != 0:
            raise Exception(
                "Unable to query OVS bond [{}] for interface [{}]: {}".format(
                    bond, interface_name, result.get("stderr", "")))
        if not result.get("stdout"):
            return None
        return bond

    def get_interface_lacp_rate_mode(self, interface_name):
        """Return the LACP rate ('fast' or 'normal') of the LAG containing interface_name."""
        bond = self._lacp_bond_for_member(interface_name)
        if bond is None:
            raise NotImplementedError(
                "LACP rate is only supported on cSONiC userspace OVS LAG members; "
                "{} is not one".format(interface_name))
        result = self._docker_exec(
            "ovs-vsctl --if-exists get Port {} other_config:lacp-time".format(bond),
            module_ignore_errors=True)
        # --if-exists makes an unset key succeed with empty output (= OVS default
        # 'slow'), so only a non-zero rc is a real failure (e.g. ovsdb-server or
        # ovs-vswitchd unavailable). Raise instead of reporting a bogus 'normal'.
        if result['rc'] != 0:
            raise Exception("Unable to get interface [{}] lacp rate from bond [{}]: {}".format(
                interface_name, bond, result['stderr']))
        return "fast" if result['stdout'].strip().strip('"') == "fast" else "normal"

    def set_interface_lacp_rate_mode(self, interface_name, mode):
        """Set the LACP rate of the LAG containing interface_name ('fast', or 'normal'/'slow')."""
        if mode not in ("fast", "normal", "slow"):
            raise ValueError("Unsupported LACP rate mode: {}".format(mode))
        bond = self._lacp_bond_for_member(interface_name)
        if bond is None:
            raise NotImplementedError(
                "LACP rate is only supported on cSONiC userspace OVS LAG members; "
                "{} is not one".format(interface_name))
        lacp_time = "fast" if mode == "fast" else "slow"
        logger.info("CsonicHost [%s] setting LACP rate of %s (%s) to %s",
                    self.container_name, interface_name, bond, lacp_time)
        result = self._docker_exec(
            "ovs-vsctl set Port {} other_config:lacp-time={}".format(bond, lacp_time))
        if result['rc'] != 0:
            raise Exception("Unable to set interface [{}] lacp rate to [{}]: {}".format(
                interface_name, mode, result['stderr']))
        return result

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

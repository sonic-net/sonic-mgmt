"""
CsonicHost - A lightweight host class for cSONiC (docker-sonic-vs) neighbor containers.

Instead of SSH/Ansible, this class uses 'docker exec' on the VM host to run commands
inside the cSONiC container. This avoids the need for sshd, admin user, or mgmt IP
inside the container.
"""

import json
import logging
import subprocess

from tests.common.devices.base import NeighborDevice

logger = logging.getLogger(__name__)


class CsonicHost(object):
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

    def shutdown(self, ifname):
        """Shut down an interface."""
        logger.info("CsonicHost [%s] shutting down %s", self.container_name, ifname)
        return self._docker_exec("ip link set {} down".format(ifname))

    def no_shutdown(self, ifname):
        """Bring up an interface."""
        logger.info("CsonicHost [%s] bringing up %s", self.container_name, ifname)
        return self._docker_exec("ip link set {} up".format(ifname))

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

    def config(self, lines=None, parents=None):
        """
        Configure via vtysh (loose compatibility with EOS config style).
        Translates config lines to vtysh commands.
        """
        if not lines:
            return {}
        cmds = []
        if parents:
            for p in parents:
                cmds.append(p)
        for line in lines:
            cmds.append(line)

        vtysh_cmd = "vtysh"
        for c in cmds:
            vtysh_cmd += " -c '{}'".format(c)

        return self._docker_exec(vtysh_cmd)

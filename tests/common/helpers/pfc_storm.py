import hashlib
import logging
import os
import pathlib
import re
import json
import time

import pytest
from jinja2 import Template
from tests.common.errors import MissingInputError
from tests.common.devices.sonic import SonicHost

TEMPLATES_DIR = os.path.realpath((os.path.join(os.path.dirname(__file__), "../../common/templates")))
ANSIBLE_ROOT = pathlib.Path(os.getenv("ANSIBLE_CONFIG",
                                      pathlib.Path(__file__).resolve().parent.joinpath("../../ansible")))
RUN_PLAYBOOK = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../scripts/exec_template.yml"))

logger = logging.getLogger(__name__)

# How long start_storm() gives pfc_gen_brcm_xgs.py on a SONiC fanout to report
# PFC_STORM_START: a fixed allowance for reading the port map from the ASIC,
# one wait for orchagent to apply the PFC transmit change, which the generator
# shares across all its interfaces (PFC_TX_ENABLE_TIMEOUT_S in
# pfc_gen_brcm_xgs.py, mirrored here), and per interface its handful of
# bcmcmd/redis/config spawns, which do not count against that wait. A healthy
# fanout reports in a few seconds; a stuck one makes the generator raise once
# the shared wait expires, which start_storm() catches as PFC_STORM_ERROR well
# before this deadline.
PFC_GEN_START_TIMEOUT_S = 40
PFC_TX_ENABLE_TIMEOUT_S = 30
PFC_GEN_PER_INTF_CMDS_S = 5
PFC_GEN_START_POLL_S = 2

# Broadcom part number -> chip name pfc_gen_brcm_xgs.py understands. Read from the
# fanout ASIC at runtime, so a new HWSKU on a known chip needs no table change.
BCM_CHIP_NAMES = {
    'BCM78900': 'Tomahawk5',
    'BCM78902': 'Tomahawk5',
    'BCM78910': 'Tomahawk6',
    'BCM78914': 'Tomahawk6',
}


def get_chip_name_if_asic_pfc_storm_supported(fanout):
    hwSkuInfo = {
        "Arista DCS-7060DX5": "Tomahawk4",
        "Arista DCS-7060PX5": "Tomahawk4",
        "Arista DCS-7060X6": "Tomahawk5",
        "Arista-7060X6": "Tomahawk5",
        "Arista-7060X6-64PE-P32O64": "Tomahawk5",
        "Arista-7060X6-64PE-O128": "Tomahawk5",
        "Arista-7060X6-64PE-O128S2": "Tomahawk5",
        "Arista-7060X6-64PE-P64": "Tomahawk5",
        "Arista-7060X6-64PE-B-P32O64": "Tomahawk5",
        "Arista-7060X6-64PE-B-O128": "Tomahawk5",
        "Arista-7060X6-64PE-B-P64": "Tomahawk5",
        "Arista DCS-7060CX": "Tomahawk",
        "Arista-7060CX": "Tomahawk",
        "Arista DCS-7260CX3": "Tomahawk2",
        "Arista-7260CX3": "Tomahawk2",
        "Arista-7260QX3": "Tomahawk2",
        "M2-W6940-64X1-FR4": "Tomahawk5",
        "Nokia-IXR7220": "Tomahawk6",
        "NH-4210-F-O256": "Tomahawk6",
        }

    for sku, chip in hwSkuInfo.items():
        if fanout.startswith(sku):
            return chip

    return None


class PFCStorm(object):
    """ PFC storm/start on different interfaces on a fanout connected to the DUT"""

    _PFC_GEN_DIR = {
        'sonic': '/tmp',
        'eos': '/mnt/flash',
    }

    def __init__(self, duthost, fanout_graph_facts, fanouthosts, **kwargs):
        """
        Args:
            duthost(AnsibleHost) : dut instance
            fanout_graph_facts(dict) : fixture that returns the fanouts connection info
            fanouthosts(AnsibleHost) : fanout instance
            kwargs(dict):
                peer_info(dict): keys are 'peerdevice', 'pfc_fanout_interface'. Optional: 'hwsku'
                pfc_gen_chip_name(string) : chip name of switch where PFC frames are generated. default: None
                pfc_queue_index(int) : queue on which the PFC storm should be generated. default: 3
                pfc_frames_number(int) : Number of PFC frames to generate. default: 100000
                pfc_gen_file(string): Script which generates the PFC traffic. default: 'pfc_gen.py'
                Other keys: 'pfc_storm_defer_time', 'pfc_storm_stop_defer_time', 'pfc_asym'
        """
        self.dut = duthost
        self.asic_type = duthost.facts['asic_type']
        hostvars = self.dut.host.options['variable_manager']._hostvars[self.dut.hostname]
        self.inventory = hostvars['inventory_file'].split('/')[-1]
        self.ip_addr = duthost.mgmt_ip
        self.fanout_info = fanout_graph_facts
        self.fanout_hosts = fanouthosts
        self.pfc_gen_file = kwargs.pop('pfc_gen_file', "pfc_gen.py")
        # deploy_pfc_gen() overrides pfc_gen_file when the fanout is XGS; keep the
        # caller's choice so a later, non-XGS fanout can be given it back
        self._pfc_gen_file_requested = self.pfc_gen_file
        self.pfc_gen_multiprocess = kwargs.pop('pfc_gen_multiprocess', False)
        self.pfc_gen_chip_name = None
        # Chip answer per fanout: one instance can walk several, and revisiting one
        # should not ask it again.
        self._xgs_chip_cache = {}
        # Fanout deploy_pfc_gen() last ran against, so a fanout switch redeploys.
        self._deployed_peer = None
        self.pfc_queue_idx = kwargs.pop('pfc_queue_index', 3)
        self.pfc_frames_number = kwargs.pop('pfc_frames_number', 100000)
        self.send_pfc_frame_interval = kwargs.pop('send_pfc_frame_interval', 0)
        self.pfc_send_period = kwargs.pop('pfc_send_period', None)
        self.peer_info = kwargs.pop('peer_info')
        self._validate_params(expected_args=['pfc_fanout_interface', 'peerdevice'])
        if 'hwsku' not in self.peer_info:
            self._populate_peer_hwsku()
        self.platform_name = None
        self.update_platform_name()
        self._populate_optional_params(kwargs)
        if self.asic_type == 'vs':
            self.peer_device = {}
            self.fanout_asic_type = ""
        else:
            self.peer_device = self.fanout_hosts[self.peer_info['peerdevice']]
            self.fanout_asic_type = self.peer_device.facts['asic_type'] \
                if isinstance(self.peer_device.host, SonicHost) else None

    def _populate_peer_hwsku(self):
        """
        Find out the hwsku associated with the fanout
        """
        if self.asic_type == 'vs':
            return
        peer_dev_info = self.fanout_info[self.peer_info['peerdevice']]['device_info']
        self.peer_info['hwsku'] = peer_dev_info['HwSku']

    def _validate_params(self, **params):
        """
        Validate if all the needed keys are present
        """
        if self.asic_type == 'vs':
            return
        expected_args = params.get('expected_args')
        peer_info_keys = list(self.peer_info.keys())
        if not all(elem in peer_info_keys for elem in expected_args):
            raise MissingInputError("Peer_info does not contain all the keys,"
                                    "Expected args: {}".format(expected_args))

    def _populate_optional_params(self, kwargs):
        """
        Create var and assign values if any the following keys are present
        'pfc_storm_defer_time', 'pfc_storm_stop_defer_time', 'pfc_asym'
        """
        if len(kwargs) > 0:
            self.__dict__.update(kwargs)
        kwargs.clear()

    def _generate_mellanox_lable_port_map(self):
        """
        In SONiC the port alias contains mellanox label port
        For example, 'etp20' contains label port '20'
        This method is used to generate port name and label port map from fanout
        """
        port_name_label_port_map = {}
        show_int_status = self.fanout_hosts[self.peer_info['peerdevice']].host.show_and_parse("show interface status")
        port_name_alias_map = {intf["interface"]: intf['alias'] for intf in show_int_status}
        for port_name, alias in port_name_alias_map.items():
            label_port = re.findall(r'\d+[a-z]?', alias)
            port_name_label_port_map[port_name] = label_port[0]
        return port_name_label_port_map

    def _generate_mellanox_label_ports(self):
        label_port_map = self._generate_mellanox_lable_port_map()
        port_names = self.peer_info['pfc_fanout_interface']
        label_ports = [label_port_map[port_name] for port_name in port_names.split(',')]

        return ",".join(label_ports)

    def _create_pfc_gen(self):
        """
        Create the pfc generation file on the fanout if it does not exist
        """
        if self.asic_type == 'vs':
            return
        pfc_gen_fpath = os.path.join(self._PFC_GEN_DIR[self.peer_device.os],
                                     self.pfc_gen_file)
        out = self.peer_device.stat(path=pfc_gen_fpath)
        if not out['stat']['exists'] or not out['stat']['isdir']:
            self.peer_device.file(path=pfc_gen_fpath, state="touch")

    def _get_eos_fanout_version(self):
        """
        Get version info for eos fanout device
        """
        cmd = 'Cli -c "show version"'
        return self.peer_device.shell(cmd)['stdout_lines']

    def _get_sonic_fanout_hwsku(self):
        """
        Get hwsku for sonic fanout device
        """
        cmd = 'show version'
        out_lines = self.peer_device.shell(cmd)['stdout_lines']
        for line in out_lines:
            if line.startswith('HwSKU:'):
                return line.split()[1]

    def _get_sonic_fanout_chip_name(self):
        """
        Chip name reported by the fanout ASIC itself, or None.

        Asking the ASIC means a new HWSKU on an already-known chip needs no table
        change, and it works for any vendor's SONiC fanout. Best effort: bcmcmd is
        silent on some fanouts (syncd down, non-Broadcom SDK), and parts absent from
        BCM_CHIP_NAMES fall back to the HWSKU table in _xgs_chip_name().
        """
        try:
            output = self.peer_device.shell('bcmcmd "show unit"')['stdout']
        except Exception as e:
            logger.info("Could not read chip from fanout ASIC: {}".format(e))
            return None
        # e.g. "Unit 0 chip BCM78900_B0 (current)"
        mo = re.search(r'chip (BCM\d+)', output)
        if not mo:
            logger.info("Fanout ASIC did not report a chip part number")
            return None
        chip_name = BCM_CHIP_NAMES.get(mo.group(1))
        logger.info("Fanout ASIC reports {} -> chip name {}".format(mo.group(1), chip_name))
        return chip_name

    def _xgs_chip_name(self):
        """
        Fanout chip name if its ASIC supports register-based PFC storm generation,
        else None. Cached per fanout -- resolving it shells out to the fanout, and
        callers update the fanout interface far more often than the fanout itself.
        """
        peer = self.peer_info['peerdevice']
        if peer not in self._xgs_chip_cache:
            if self.peer_device.os == 'eos':
                chip_name = get_chip_name_if_asic_pfc_storm_supported(
                    self._get_eos_fanout_version()[0])
            elif self.peer_device.os == 'sonic':
                # Prefer what the ASIC reports; fall back to the HWSKU table so
                # fanouts where bcmcmd is unavailable keep working as before.
                chip_name = (self._get_sonic_fanout_chip_name() or
                             get_chip_name_if_asic_pfc_storm_supported(
                                 self._get_sonic_fanout_hwsku()))
            else:
                chip_name = None
            self._xgs_chip_cache[peer] = chip_name
        return self._xgs_chip_cache[peer]

    def deploy_pfc_gen(self):
        """
        Deploy the pfc generation file on the fanout
        """
        if self.asic_type == 'vs':
            return
        if self.peer_device.os in ('eos', 'sonic'):
            self._select_xgs_generator()
            src_pfc_gen_file = "common/helpers/{}".format(self.pfc_gen_file)
            self._create_pfc_gen()
            if self.fanout_asic_type == 'mellanox':
                src_pfc_gen_file = f"../ansible/roles/test/files/mlnx/docker-tests-pfcgen-asic/{self.pfc_gen_file}"
            self.peer_device.copy(
                src=src_pfc_gen_file,
                dest=self._PFC_GEN_DIR[self.peer_device.os]
                )
            if self.fanout_asic_type == 'mellanox':
                cmd = f"docker cp {self._PFC_GEN_DIR[self.peer_device.os]}/{self.pfc_gen_file} syncd:/root/"
                self.peer_device.shell(cmd)
        self._deployed_peer = self.peer_info['peerdevice']

    def _ensure_pfc_gen_deployed(self):
        """
        Deploy the generator if the fanout changed since the last deploy.

        Callers that walk several fanouts do not all call deploy_pfc_gen() again on a
        fanout they have visited before, but the generator on the fanout, the file
        name rendered into the template and the chip name passed to it all have to
        describe the same fanout.
        """
        if self.asic_type == 'vs':
            return
        if self._deployed_peer != self.peer_info['peerdevice']:
            self.deploy_pfc_gen()

    def update_queue_index(self, q_idx):
        """
        Update the queue index. Can be invoked after the class init to change the queue index
        """
        self.pfc_queue_idx = q_idx

    def update_peer_info(self, peer_info):
        """
        Update the fanout info. Can be invoked after the class init to change the fanout or fanout interface
        """
        if self.asic_type == 'vs':
            return
        self._validate_params(expected_args=['peerdevice', 'pfc_fanout_interface'])
        for key in peer_info:
            self.peer_info[key] = peer_info[key]
        if 'hwsku' not in peer_info:
            self._populate_peer_hwsku()
        self.update_platform_name()
        self.peer_device = self.fanout_hosts[self.peer_info['peerdevice']]
        # The fanout may have changed, and this was resolved once in __init__ and
        # never since. _xgs_chip_name() and the deployed generator key off the
        # fanout themselves.
        self.fanout_asic_type = self.peer_device.facts['asic_type'] \
            if isinstance(self.peer_device.host, SonicHost) else None

    def update_platform_name(self):
        """
        Identifies the fanout platform
        """
        if self.asic_type == 'vs':
            return
        if 'arista' in self.peer_info['hwsku'].lower():
            self.platform_name = 'arista'
        elif 'MLNX-OS' in self.peer_info['hwsku']:
            self.platform_name = 'mlnx'

    def _select_xgs_generator(self):
        """
        Switch to pfc_gen_brcm_xgs.py when the fanout is a Broadcom XGS switch.

        Called from deploy_pfc_gen() and from every template render, so a handle
        that never deployed (test_pfcwd_warm_reboot deploys once per fanout and
        shares the copy between its per-port handles) still runs the generator
        that was copied, with the chip name it needs, instead of the default
        pfc_gen.py that is not on the fanout.
        """
        chip_name = self._xgs_chip_name()
        if chip_name:
            self.pfc_gen_file = "pfc_gen_brcm_xgs.py"
            self.pfc_gen_file_test_name = "pfc_gen_brcm_xgs.py"
            self.pfc_gen_chip_name = chip_name
        else:
            # This instance may have been pointed at an XGS fanout before;
            # a fanout that cannot run that generator must not inherit it.
            self.pfc_gen_file = self._pfc_gen_file_requested
            self.pfc_gen_file_test_name = self._pfc_gen_file_requested
            self.pfc_gen_chip_name = None

    def _uses_xgs_generator(self):
        """
        True when the storm is driven by pfc_gen_brcm_xgs.py on a SONiC fanout,
        the only generator whose start-up start_storm() can watch. Keyed off the
        fanout's chip, as the template choice is, not off deploy_pfc_gen() having
        run on this handle.
        """
        return (self.asic_type != 'vs' and self.peer_device.os == 'sonic' and
                bool(self._xgs_chip_name()))

    def _pfc_gen_log_path(self):
        """
        Log file the generator's stdout/stderr go to on the fanout.

        Named after the storm's interfaces and queue so generators running at
        the same time (one per port and queue on the warm-reboot tests) each
        keep their own. Many-port storms get a hash rather than a 400-character
        file name.
        """
        intfs = self.peer_info['pfc_fanout_interface'].split(',')
        if len(intfs) == 1:
            label = intfs[0]
        else:
            digest = hashlib.md5(",".join(intfs).encode()).hexdigest()[:8]
            label = "{}_plus{}_{}".format(intfs[0], len(intfs) - 1, digest)
        return "{}/pfc_gen_{}_q{}.log".format(self._PFC_GEN_DIR['sonic'], label, self.pfc_queue_idx)

    def _update_template_args(self):
        """
        Populates all the vars needed by the pfc storm templates
        """
        if self.asic_type != 'vs' and self.peer_device.os in ('eos', 'sonic'):
            self._select_xgs_generator()
        self.extra_vars = {
            "pfc_gen_file": self.pfc_gen_file,
            "pfc_queue_index": self.pfc_queue_idx,
            "pfc_frames_number": self.pfc_frames_number,
            "pfc_fanout_interface": self.peer_info['pfc_fanout_interface'] if self.asic_type != 'vs' else "",
            "pfc_gen_chip_name": self.pfc_gen_chip_name,
            "ansible_eth0_ipv4_addr": self.ip_addr,
            "peer_hwsku": self.peer_info['hwsku'] if self.asic_type != 'vs' else "",
            "send_pfc_frame_interval": self.send_pfc_frame_interval,
            "pfc_send_period": self.pfc_send_period
            }
        if getattr(self, "pfc_storm_defer_time", None):
            self.extra_vars.update({"pfc_storm_defer_time": self.pfc_storm_defer_time})
        if getattr(self, "pfc_storm_stop_defer_time", None):
            self.extra_vars.update({"pfc_storm_stop_defer_time": self.pfc_storm_stop_defer_time})
        if getattr(self, "pfc_asym", None):
            self.extra_vars.update({"pfc_asym": self.pfc_asym})
        if self.asic_type in ["mellanox", "broadcom"]:
            self.extra_vars.update({"pfc_gen_multiprocess": True})

        if self.asic_type != 'vs':
            if self.peer_device.os in self._PFC_GEN_DIR:
                self.extra_vars['pfc_gen_dir'] = self._PFC_GEN_DIR[self.peer_device.os]
            if self.fanout_asic_type == 'mellanox' and self.peer_device.os == 'sonic':
                self.extra_vars.update({"pfc_fanout_label_port": self._generate_mellanox_label_ports()})
            if self._uses_xgs_generator():
                self.extra_vars['pfc_gen_log'] = self._pfc_gen_log_path()

    def _prepare_start_template(self):
        """
        Populates the pfc storm start template
        """
        self._update_template_args()
        if self.asic_type == 'vs':
            self.pfc_start_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_eos.j2")
        elif (self.dut.topo_type == 't2' and self.peer_device.os == 'sonic' and
              not self.pfc_gen_chip_name):
            self.pfc_start_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_{}_t2.j2".format(self.peer_device.os))
        elif self.fanout_asic_type == 'mellanox' and self.peer_device.os == 'sonic':
            self.pfc_start_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_mlnx_{}.j2".format(self.peer_device.os))
        elif self.pfc_gen_chip_name:
            self.pfc_start_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_arista_{}.j2".format(self.peer_device.os))
        else:
            self.pfc_start_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_{}.j2".format(self.peer_device.os))
        self.extra_vars.update({"template_path": self.pfc_start_template})

    def _prepare_stop_template(self):
        """
        Populates the pfc storm stop template
        """
        self._update_template_args()
        if self.asic_type == 'vs':
            self.pfc_stop_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_stop_eos.j2")
        elif (self.dut.topo_type == 't2' and self.peer_device.os == 'sonic' and
              not self.pfc_gen_chip_name):
            self.pfc_stop_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_stop_{}_t2.j2".format(self.peer_device.os))
        elif self.fanout_asic_type == 'mellanox' and self.peer_device.os == 'sonic':
            self.pfc_stop_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_stop_mlnx_{}.j2".format(self.peer_device.os))
        elif self.pfc_gen_chip_name:
            self.pfc_stop_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_stop_arista_{}.j2".format(self.peer_device.os))
        else:
            self.pfc_stop_template = os.path.join(
                TEMPLATES_DIR, "pfc_storm_stop_{}.j2".format(self.peer_device.os))
        self.extra_vars.update({"template_path": self.pfc_stop_template})

    def _run_pfc_gen_template(self):
        """
        Run pfc generator script on a specific OS type.

        Returns the shell result on a SONiC fanout, else None.
        """
        if self.asic_type == 'vs':
            return None
        if self.peer_device.os == 'sonic':
            with open(self.extra_vars['template_path']) as tmpl_fd:
                tmpl = Template(tmpl_fd.read())
                cmds = tmpl.render(**self.extra_vars).splitlines()
            cmds = (_.strip() for _ in cmds)
            cmd = "; ".join(_ for _ in cmds if _)
            logger.info("Running command: {}".format(cmd))
            return self.peer_device.shell(cmd, module_ignore_errors=True)
        else:
            # TODO: replace this playbook execution with Mellanox
            # onyx_config/onyx_command modules
            logger.info("Running Template: {}".format(json.dumps(self.extra_vars)))

            self.peer_device.exec_template(
                ANSIBLE_ROOT, RUN_PLAYBOOK,
                self.inventory, **self.extra_vars
                )
            return None

    def _wait_storm_started(self, launch_result):
        """
        Block until pfc_gen_brcm_xgs.py prints PFC_STORM_START, or fail the test.

        The generator runs detached under nohup. Before this, a storm it never
        managed to assert (orchagent on the fanout stuck, so the PFC enable it
        waits for never lands) only showed up 10 s later as a missing
        "detected PFC storm" line on the DUT and was filed against pfcwd. Now
        it fails here, naming the fanout and quoting the generator's own output.
        """
        fanout = self.peer_info['peerdevice']
        intfs = self.peer_info['pfc_fanout_interface']
        log = self.extra_vars['pfc_gen_log']
        mo = re.search(r'pfc_gen_pid=(\d+)', (launch_result or {}).get('stdout', ''))
        pid = mo.group(1) if mo else None
        timeout = (PFC_GEN_START_TIMEOUT_S + PFC_TX_ENABLE_TIMEOUT_S
                   + PFC_GEN_PER_INTF_CMDS_S * len(intfs.split(',')))

        # One round trip per poll: the log tail, then whether the generator is alive.
        probe = "tail -n 20 {} 2>/dev/null".format(log)
        if pid:
            probe += "; [ -d /proc/{} ] && echo pfc_gen_alive || echo pfc_gen_exited".format(pid)
        started = time.time()
        while True:
            lines = self.peer_device.shell(probe, module_ignore_errors=True).get('stdout', '').splitlines()
            exited = 'pfc_gen_exited' in lines
            log_lines = [_ for _ in lines if _ not in ('pfc_gen_alive', 'pfc_gen_exited')]
            if any(_.startswith('PFC_STORM_START') for _ in log_lines):
                logger.info("PFC storm on {} {} asserted after {:.1f}s"
                            .format(fanout, intfs, time.time() - started))
                return
            if any(_.startswith('PFC_STORM_ERROR') for _ in log_lines):
                reason = "the generator reported an error"
                break
            if exited:
                reason = "the generator (pid {}) exited without reporting PFC_STORM_START".format(pid)
                break
            if time.time() - started > timeout:
                reason = "no PFC_STORM_START from the generator within {}s".format(timeout)
                # Still running, so nobody else will stop it: callers only call
                # stop_storm() once start_storm() has returned. Left alone it
                # would assert PFC on the port whenever orchagent catches up,
                # with no test left to clear it. Its SIGTERM handler clears
                # whatever it has configured so far.
                self.stop_storm()
                break
            time.sleep(PFC_GEN_START_POLL_S)

        hint = ""
        if any("PFC transmit not " in _ for _ in log_lines):
            hint = ("; the fanout never applied the PFC transmit change, "
                    "so its orchagent is probably stuck")
        pytest.fail("fanout {}: PFC storm never started on {} (queue {}): {}{}.\n"
                    "Last lines of {} on the fanout:\n{}"
                    .format(fanout, intfs, self.pfc_queue_idx, reason, hint,
                            log, "\n".join(log_lines) or "<empty>"))

    def start_storm(self):
        """
        Starts PFC storm on the fanout interfaces

        On a SONiC fanout driven by pfc_gen_brcm_xgs.py this returns only once
        the generator has asserted the storm, and fails the test if it never
        does. A deferred start (pfc_storm_defer_time) is not waited for: the
        caller wants the storm to begin later, while it does something else.
        """
        self._ensure_pfc_gen_deployed()
        self._prepare_start_template()
        if self.asic_type == 'vs':
            return
        logger.info("--- Starting PFC storm on {} on interfaces {} on queue {} ---"
                    .format(self.peer_info['peerdevice'],
                            self.peer_info['pfc_fanout_interface'],
                            self.pfc_queue_idx))
        launch_result = self._run_pfc_gen_template()
        if self._uses_xgs_generator() and not getattr(self, "pfc_storm_defer_time", None):
            self._wait_storm_started(launch_result)

    def stop_storm(self):
        """
        Stops PFC storm on the fanout interfaces
        """
        self._ensure_pfc_gen_deployed()
        self._prepare_stop_template()
        if self.asic_type == 'vs':
            return
        logger.info("--- Stopping PFC storm on {} on interfaces {} on queue {} ---"
                    .format(self.peer_info['peerdevice'],
                            self.peer_info['pfc_fanout_interface'],
                            self.pfc_queue_idx))
        self._run_pfc_gen_template()


class PFCMultiStorm(object):
    """ PFC storm start/stop on multiple fanouts connected to the DUT"""
    def __init__(self, duthost, fanout_graph_facts, fanouthosts, peer_params):
        """
        Args:
            duthost(AnsibleHost) : dut instance
            fanout_graph_facts(dict) : fixture that returns the fanouts connection info
            fanouthosts(AnsibleHost) : fanout instance
            peer_params(dict) : contains all the params needed for pfc storm
               eg. peer_params = {'peerdevice':
                                     {'pfc_gen_file': pfc_gen_file,
                                      'pfc_frames_number': frame count sent on all intf in the inf_list,
                                      'pfc_queue_index': q_index for the pfc storm on all intf in the intf list,
                                      'intfs': [intf_1, intf_2]
                                     }
                                 }
            pfc_queue_index(int) : queue on which the PFC storm should be generated. default: 4
            pfc_frames_number(int) : Number of PFC frames to generate. default: 100000000
            pfc_gen_file(string): Script which generates the PFC traffic. default: pfc_gen.py
            storm_handle(dict): PFCStorm instance for each fanout connected to the DUT
        """
        self.duthost = duthost
        self.asic_type = duthost.facts['asic_type']
        self.fanout_graph = fanout_graph_facts
        self.fanouthosts = fanouthosts
        self.peer_params = peer_params
        self.pfc_queue_index = 4
        self.pfc_frames_number = 100000000
        self.pfc_gen_file = "pfc_gen.py"
        self.storm_handle = dict()

    def _get_pfc_params(self, peer_dev):
        """
        Populate the pfc params value with the ones in peer_params dict if available

        Args:
            peer_dev(string): fanout name

        Returns:
            q_idx(int): PFC queue where PFC storm should be generated on that fanout
            frames_cnt(int): Number of PFC frames to be sent from the fanout
            gen_file(string): Name of pfc storm generation script
        """
        q_idx = self.pfc_queue_index
        frames_cnt = self.pfc_frames_number
        gen_file = self.pfc_gen_file
        if 'pfc_frames_number' in self.peer_params[peer_dev]:
            frames_cnt = self.peer_params[peer_dev]['pfc_frames_number']
        if 'pfc_queue_index' in self.peer_params[peer_dev]:
            q_idx = self.peer_params[peer_dev]['pfc_queue_index']
        if 'pfc_gen_file' in self.peer_params[peer_dev]:
            gen_file = self.peer_params[peer_dev]['pfc_gen_file']
        return q_idx, frames_cnt, gen_file

    def set_storm_params(self):
        """
        Construct the peer info and deploy the pfc gen script on the fanouts
        """
        for peer_dev in self.peer_params:
            if self.asic_type == 'vs':
                peer_info = {}
            else:
                peer_dev_info = self.fanout_graph[peer_dev]['device_info']
                peer_info = {'peerdevice': peer_dev,
                             'hwsku': peer_dev_info['HwSku'],
                             'pfc_fanout_interface': self.peer_params[peer_dev]['intfs']}

            q_idx, frames_cnt, gen_file = self._get_pfc_params(peer_dev)
            if self.duthost.topo_type == 't2' and self.fanouthosts[peer_dev].os == 'sonic':
                gen_file = 'pfc_gen_t2.py'
                pfc_send_time = 60
            else:
                gen_file = 'pfc_gen.py'
                pfc_send_time = None
            # get pfc storm handle
            self.storm_handle[peer_dev] = PFCStorm(self.duthost, self.fanout_graph,
                                                   self.fanouthosts,
                                                   pfc_queue_index=q_idx,
                                                   pfc_frames_number=frames_cnt,
                                                   pfc_gen_file=gen_file,
                                                   pfc_send_period=pfc_send_time,
                                                   peer_info=peer_info)

            self.storm_handle[peer_dev].deploy_pfc_gen()

    def start_pfc_storm(self):
        """
        Start PFC storm on all fanouts connected to the DUT
        """
        for hndle in self.storm_handle:
            self.storm_handle[hndle].start_storm()

    def stop_pfc_storm(self):
        """
        Stop PFC storm on all fanouts connected to the DUT
        """
        for hndle in self.storm_handle:
            self.storm_handle[hndle].stop_storm()

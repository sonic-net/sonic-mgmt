import os
import re
import copy
import json
import shutil
import tempfile
from random import Random
from itertools import permutations
from collections import OrderedDict

from spytest.ordyaml import OrderedYaml
from spytest.dicts import SpyTestDict
from spytest.logger import getNoneLogger
from spytest import env
from spytest.st_time import get_timenow
from spytest.st_time import get_elapsed

import utilities.common as utils

testbeds_root = os.path.join(os.path.dirname(__file__), '..')
testbeds_root = os.path.join(os.path.abspath(testbeds_root), "testbeds")


class Testbed(object):
    max_dut_models = 8

    def __init__(self, filename=None, logger=None, cfg=None,
                 flex_dut=False, flex_port=False, topo_index=None):
        self._paths = []
        self._paths.append(env.get("SPYTEST_USER_ROOT"))
        self._paths.append(testbeds_root)
        self.validation_errors = []
        self.name = None
        self.oyaml = None
        self.oyaml_data = None
        self.oyaml_data_copy = None
        self.offset = None
        self.common_tgen_ports = True
        self.expand_yaml = False
        self.use_aliases = True
        if topo_index is None:
            self.defaut_topo_index = 0
        else:
            self.defaut_topo_index = topo_index
        self.current_topo_index = self.defaut_topo_index
        self.cfg = cfg
        self.max_match_time = env.getint("SPYTEST_TESTBED_MAX_MATCH_TIME", 120)
        self.ignore_constraints = env.get("SPYTEST_TESTBED_IGNORE_CONSTRAINTS", "")
        if self.ignore_constraints:
            self.ignore_constraints = utils.split_byall(self.ignore_constraints, True)
        if cfg:
            self.flex_dut = bool(env.get("SPYTEST_FLEX_DUT", "1") == "1")
            self.flex_port = bool(env.get("SPYTEST_FLEX_PORT", "0") == "1")
            self.filemode = cfg.filemode
            self.exclude_devices = cfg.exclude_devices
            self.include_devices = cfg.include_devices
        else:
            self.flex_dut = flex_dut
            self.flex_port = flex_port
            self.filemode = False
            self.exclude_devices = env.get("SPYTEST_TESTBED_EXCLUDE_DEVICES")
            self.include_devices = env.get("SPYTEST_TESTBED_INCLUDE_DEVICES")
        self.device_name_map = {}
        self.rename_devices = env.get("SPYTEST_TESTBED_RENAME_DEVICES")
        if self.rename_devices:
            self.rename_devices = utils.split_byall(self.rename_devices, True)
        self.reorder_devices = env.get("SPYTEST_TESTBED_REORDER_DEVICES")
        if self.reorder_devices:
            self.reorder_devices = utils.split_byall(self.reorder_devices, True)
        if self.exclude_devices:
            self.exclude_devices = utils.split_byall(self.exclude_devices, True)
        if self.include_devices:
            self.include_devices = utils.split_byall(self.include_devices, True)
        self.derived = SpyTestDict(duts=None, down_ports=None)
        self.profiles = SpyTestDict()
        self.topologies = SpyTestDict()
        # per topology profile info
        self.all_breakouts = SpyTestDict()
        self.all_links = SpyTestDict()
        self.all_reserved_links = SpyTestDict()
        self.all_unconnected_links = SpyTestDict()
        # per topology profile info
        self.devices = SpyTestDict()
        self.colors = SpyTestDict()
        self.services = SpyTestDict()
        self.overrides = SpyTestDict()
        self.configs = SpyTestDict()
        self.builds = SpyTestDict()
        self.errors = SpyTestDict()
        self.speeds = SpyTestDict()
        self.instrument = SpyTestDict()
        self.build_default_errors()
        self.params = SpyTestDict()
        self.global_params = SpyTestDict()
        self.set_validity(None)
        self.logger = logger or getNoneLogger()
        self._load_and_check(filename)
        self.current_topo_index = self.defaut_topo_index

    def _debug(self, msg):
        self.logger.debug(msg)

    def _debug2(self, msg):
        pass

    def _locate(self, filename):
        for path in self._paths:
            filename1 = os.path.join(path, filename)
            if os.path.isfile(filename1):
                return filename1
        if os.path.isfile(filename):
            return filename
        return None

    def build_default_errors(self):
        default = SpyTestDict()
        default.containing_error = SpyTestDict()
        default.containing_error.command = ".*"
        default.containing_error.search = ".*Error:.*"
        default.containing_error.action = ["raise"]
        default.containing_bang = SpyTestDict()
        default.containing_bang.command = ".*"
        default.containing_bang.search = ".*\\^.*"
        default.containing_bang.action = ["raise"]
        self.errors.default = default

    def __del__(self):
        pass

    def is_valid(self):
        return self.valid

    def get_file_path(self):
        return self.oyaml.get_file_path()

    def get_raw(self, expanded=False):
        return self.oyaml.get_raw(expanded)

    def get_dut_access(self, dut_id):
        retval, profile = SpyTestDict(), self.get_profile()
        for dinfo in profile.topology.devices.values():
            if dinfo["__name__"] == dut_id:
                retval["dut_name"] = dinfo.__name0__
                retval["alias"] = dinfo.alias
                retval["ip"] = dinfo.access.ip
                retval["port"] = dinfo.access.port
                retval["rest_ip"] = dinfo.access.get("rest_ip", None)
                retval["rest_port"] = dinfo.access.get("rest_port", None)
                retval["rest_protocol"] = dinfo.access.get("rest_protocol", None)
                retval["mgmt_ipmask"] = dinfo.access.get("mgmt_ipmask", None)
                retval["mgmt_gw"] = dinfo.access.get("mgmt_gw", None)
                retval["mgmt_ifname"] = dinfo.access.get("mgmt_ifname", None)
                retval["username"] = dinfo.credentials.username
                retval["password"] = dinfo.credentials.password
                retval["altpassword"] = dinfo.credentials.altpassword
                retval["username"] = env.get("SPYTEST_OVERRIDE_USERNAME", retval["username"])
                passwords = env.get("SPYTEST_OVERRIDE_PASSWORD", None)
                if passwords:
                    passwords = passwords.split(",")
                    if len(passwords) > 0:
                        retval["password"] = passwords[0]
                    if len(passwords) > 1:
                        retval["altpassword"] = passwords[1]
                    if len(passwords) > 2:
                        retval["oniepassword"] = passwords[2]
                utils.dict_copy(dinfo.credentials, retval, "oniepassword")
                retval["auth"] = dinfo.credentials.get("auth", None)
                retval["errors"] = self.get_error(dut_id, None)
                mgmt_ifname = env.get("SPYTEST_MGMT_IFNAME", "eth0")
                mgmt_ifname = self.get_device_param(dut_id, "mgmt_ifname", mgmt_ifname)
                retval["mgmt_ifname"] = retval["mgmt_ifname"] or mgmt_ifname
                restore_build = self.get_build(dut_id, "restore")
                current_build = self.get_build(dut_id, "current")
                if restore_build:
                    retval["onie_image"] = restore_build
                elif current_build:
                    retval["onie_image"] = current_build
                else:
                    retval["onie_image"] = None
                if dinfo.device_type in ["fastpath"]:
                    device_model = "fastpath"
                elif dinfo.device_type in ["icos"]:
                    device_model = "icos"
                elif dinfo.device_type in ["linux"]:
                    device_model = "linux"
                elif dinfo.device_type in ["poe"]:
                    device_model = "poe"
                else:
                    device_model = "sonic"
                protocol = env.get("SPYTEST_OVERRIDE_ACCESS_PROTOCOL")
                if protocol:
                    dinfo.access.protocol = protocol
                if dinfo.access.protocol == "ssh":
                    retval["access_model"] = "{}_ssh".format(device_model)
                    if "ssh_port" in dinfo.access:
                        retval["port"] = dinfo.access.ssh_port
                    if "ssh_ip" in dinfo.access:
                        retval["ip"] = dinfo.access.ssh_ip
                elif dinfo.access.protocol == "sshcon":
                    retval["access_model"] = "{}_sshcon".format(device_model)
                    if "sshcon_username" in dinfo.access:
                        retval["sshcon_username"] = dinfo.access.sshcon_username
                    elif "username" in dinfo.access:
                        retval["sshcon_username"] = dinfo.access.username
                    if "sshcon_password" in dinfo.access:
                        retval["sshcon_password"] = dinfo.access.sshcon_password
                    elif "password" in dinfo.access:
                        retval["sshcon_password"] = dinfo.access.password
                    if "sshcon_port" in dinfo.access:
                        retval["port"] = dinfo.access.sshcon_port
                    if "sshcon_ip" in dinfo.access:
                        retval["ip"] = dinfo.access.sshcon_ip
                else:
                    retval["access_model"] = "{}_terminal".format(device_model)
                retval["device_model"] = device_model
                return retval
        return None

    def get_device_info(self, name, dtype=None):
        profile = self.get_profile()
        for dinfo in profile.topology.devices.values():
            if not dtype or dinfo.type == dtype:
                if dinfo["__name__"] == name:
                    return dinfo
        return None

    def get_device_alias(self, name, only=False, retid=False):
        profile = self.get_profile()
        for dinfo in profile.topology.devices.values():
            if dinfo.__name__ == name or dinfo.__name0__ == name:
                if only:
                    return dinfo.__name0__ if retid else dinfo.alias
                return "{}({})".format(dinfo.__name0__, dinfo.alias)
        return "UNKNOWN-DEVICE-{}".format(name)

    def _load_and_check(self, filename):
        # testbed file order: argument, env, default
        if not filename:
            filename = env.get("SPYTEST_TESTBED_FILE", "testbed.yaml")
        if self._load_yaml(filename):
            self.valid = True
            if self._build_link_info():
                self._validate()

    def set_validity(self, msg, valid=False):
        if msg:
            self.logger.error(msg)
            self.validation_errors.append(msg)
        self.valid = valid

    def _validate(self):
        self.validation_errors = []
        self._validate_passwords()
        self._validate_config_files()
        # tg_ips = self._validate_tgen_info()
        # rps_ips = self._validate_rps_info(tg_ips)
        # self._validate_consoles(tg_ips, rps_ips, [])
        self._validate_links()

    # verify duplicate access details
    def _validate_consoles(self, tg_ips, rps_ips, exclude):
        consoles, profile = [], self.get_profile()
        for dev, dinfo in profile.topology.devices.items():
            if dinfo.type != "DUT":
                continue
            access = dinfo.access
            if access.ip in tg_ips:
                msg = "{}: IP {} already used for TG".format(dev, access.ip)
                self.set_validity(msg)
            if access.ip in rps_ips and dinfo.device_type not in ["sonicvs", "vsonic", "veos"]:
                msg = "{}: IP {} already used for RPS".format(dev, access.ip)
                self.set_validity(msg)
            ent = "{}:{}:{}".format(access.protocol, access.ip, access.port)
            if ent in exclude:
                msg = "{}: already used".format(ent)
                self.set_validity(msg)
            if ent not in consoles:
                consoles.append(ent)
                continue
            msg = "Duplicate console info {}".format(ent)
            self.set_validity(msg, True)
        return consoles

    # verify duplicate TG IP addresses
    def _validate_tgen_info(self):
        versions = dict()
        types = dict()
        ix_servers = []
        for dev in self.get_device_names("TG"):
            tinfo = self.get_tg_info(dev)
            if tinfo["type"] not in versions:
                versions[tinfo.type] = tinfo.version
            elif versions[tinfo.type] != tinfo.version:
                msg = "multiple versions ({}, {}) of same TG type not supported"
                msg = msg.format(versions[tinfo.type], tinfo.version)
                self.set_validity(msg)
            for ip in utils.make_list(tinfo.ip):
                if ip not in types:
                    types[ip] = tinfo.type
                elif types[ip] != tinfo.type:
                    msg = "same ip ({}) cant be used for multiple TG types"
                    msg = msg.format(ip)
                    self.set_validity(msg)
        for dev in self.get_device_names("TG"):
            tinfo = self.get_tg_info(dev)
            if "ix_server" in tinfo:
                for ix_server in utils.make_list(tinfo.ix_server):
                    if ix_server in ix_servers:
                        continue
                    ix_servers.append(ix_server)
                    for ip in utils.make_list(tinfo.ip):
                        if ix_server in types and ip != ix_server:
                            msg = "ix_server ip ({}) already used as TG IP"
                            msg = msg.format(ix_server)
                            self.set_validity(msg)
        ix_servers.extend(types.keys())
        return ix_servers

    # verify duplicate RPS IP addresses
    def _validate_rps_info(self, tg_ips):
        outlets = dict()
        models = dict()
        for dev in self.get_device_names("DUT"):
            tinfo = self.get_rps(dev)
            if not tinfo:
                continue
            tinfo = tinfo[0]  # TODO: verify all
            if tinfo.ip not in models:
                models[tinfo.ip] = tinfo.model
            elif models[tinfo.ip] != tinfo.model:
                msg = "same ip ({}) cant be used for multiple RPS models"
                msg = msg.format(tinfo.ip)
                self.set_validity(msg)
        for dev in self.get_device_names("DUT"):
            tinfo = self.get_rps(dev)
            if not tinfo:
                continue
            tinfo = tinfo[0]  # TODO: verify all
            if tinfo.model in ["vsh", "sonicvs", "vsonic", "veos"]:
                continue
            if tinfo.ip not in outlets:
                outlets[tinfo.ip] = []
            if tinfo.outlet in outlets[tinfo.ip]:
                msg = "RPS outlet ({}/{}) is already used"
                msg = msg.format(tinfo.ip, tinfo.outlet)
                self.set_validity(msg)
            else:
                outlets[tinfo.ip].append(tinfo.outlet)
        for ip in outlets:
            if ip in tg_ips:
                msg = "RPS IP {} already used for TG".format(ip)
                self.set_validity(msg)
        return outlets.keys()

    def _validate_links(self):
        pairs = dict()
        for dev in self.get_device_names():
            for local, partner, remote in self.get_links(dev):
                # alias = self.get_device_alias(dev)
                # pair = "{}/{}".format(alias, local)
                pair = "{}/{}".format(dev, local)
                # palias = self.get_device_alias(partner)
                # to = "{}/{}".format(palias, remote)
                to = "{}/{}".format(partner, remote)
                if pair in pairs:
                    msg = "Duplicate Links {} {} connecting to {}"
                    msg = msg.format(pairs[pair], to, pair)
                    self.logger.error(msg)
                    self.set_validity(msg)
                else:
                    pairs[pair] = to

    # verify same passwords
    def _validate_passwords(self):
        for dev, dinfo in self.devices.items():
            if dinfo.type != "DUT" or dinfo.get("reserved", False):
                continue
            if self.get_device_type(dev) != "sonic":
                continue
            if not dinfo.credentials.password or not dinfo.credentials.altpassword:
                continue
            if dinfo.credentials.password in dinfo.credentials.altpassword or \
                    dinfo.credentials.altpassword in dinfo.credentials.password:
                msg = "password and altpasswords are alike for device {}".format(dev)
                self.set_validity(msg)

    # verify presence of config files if specified
    def _validate_config_files(self):
        for dut in self.get_device_names("DUT"):
            # verify services
            if not self.get_service(dut, None):
                msg = "invalid services for {}".format(dut)
                self.set_validity(msg)
            # verify builds
            if not self.get_build(dut, None):
                msg = "invalid build for {}".format(dut)
                self.set_validity(msg)
            # verify configs section
            if not self.get_config(dut, None):
                msg = "invalid config for {}".format(dut)
                self.set_validity(msg)
                continue
            # verify config files
            for scope in ["current", "restore"]:
                files = self.get_config(dut, scope)
                if files is None:
                    if scope in ["current", "restore"]:
                        self.set_validity(None)
                    continue
                for filename in files:
                    file_path = self.get_config_file_path(filename)
                    if file_path:
                        continue
                    msg = "{} config file {} not found".format(scope, filename)
                    self.logger.error(msg)
                    if not self.filemode:
                        self.set_validity(None)

    def _is_ignored_device(self, dut):
        if dut in self.devices:
            reserved = str(self.devices[dut].get("reserved", False))
            return bool(reserved not in ["False", "0"])
        return True

    def _override_link_params(self):
        if self.cfg and self.cfg.link_param:
            for d, l, k, v in self.cfg.link_param:
                self._override_link_param(d, l, k, v)

    def _override_link_param(self, d, ll, k, v):
        profile = self.get_profile()
        for dut, dinfo in profile.topology.devices.items():
            if d != "__all__" and d != dut:
                continue
            if not dinfo or "interfaces" not in dinfo:
                continue
            for link, linfo in dinfo.interfaces.items():
                if ll != "__all__" and ll != link:
                    continue
                msg = "Change Link {}/{} Param {} to {}"
                msg = msg.format(dut, ll, k, v)
                self.logger.warning(msg)
                linfo[k] = v

    def _override_dev_params(self):
        if self.cfg and self.cfg.dev_param:
            for d, k, v in self.cfg.dev_param:
                self._override_dev_param(d, k, v)

    def _override_dev_param(self, d, k, v):
        found = False
        for devname, dinfo in self.devices.items():
            if "params" not in dinfo:
                dinfo.params = SpyTestDict()
            valid = ["__all__", devname]
            try:
                valid.append(dinfo.__name0__)
            except Exception:
                pass
            if d in valid:
                msg = "Changing Device {} Param {} from '{}' to '{}'"
                msg = msg.format(devname, k, dinfo.params.get(k, ""), v)
                self.logger.warning(msg)
                dinfo.params[k] = v
                found = True
        if not found:
            msg = "Failed to Change Device {} Param {} to '{}'"
            msg = msg.format(d, k, v)
            self.logger.warning(msg)

    def _build_link_info(self):
        retval = True
        for profile in self.get_all_profiles():
            retval = retval and self._build_profile_link_info(profile)
        return retval

    def _build_profile_link_info(self, profile):
        self.set_topo_index(profile.index)
        # utils.print_data(profile.topology, "topology-1")

        # ensure we have device type
        for dev, dinfo in self.devices.items():
            dinfo.type = "DUT" if dinfo.device_type != "TGEN" else "TG"
            # reserve the devices from include and exclude list
            if self.include_devices:
                if str(dev) not in self.include_devices:
                    dinfo.reserved = True
                    msg = "reserving device {} as it is NOT IN include_list"
                    msg = msg.format(dev)
                    self.logger.warning(msg)
            elif self.exclude_devices:
                if str(dev) in self.exclude_devices:
                    dinfo.reserved = True
                    msg = "reserving device {} as it is IN exclude_list"
                    msg = msg.format(dev)
                    self.logger.warning(msg)

        # add devices if missing in topology but present in connections
        add_devices, unreserved_devices = [], SpyTestDict()

        # remove reserved/ignored devices from topology
        for dut, dinfo in profile.topology.devices.items():
            if not self._is_ignored_device(dut):
                unreserved_devices[dut] = dinfo
        profile.topology.devices = unreserved_devices

        # remove invalid interface sections
        for dut, dinfo in profile.topology.devices.items():
            if not dinfo or "interfaces" not in dinfo:
                continue
            if not isinstance(dinfo.interfaces, dict):
                msg = "interfaces section of {} is invalid - ignoring".format(dut)
                self.logger.warning(msg)
                del dinfo.interfaces
                continue

        # override link params from command line
        self._override_link_params()

        # parse interfaces
        connected_links, reserved_links, unconnected_links = [], [], []
        for dut, dinfo in profile.topology.devices.items():
            if not dinfo or "interfaces" not in dinfo:
                continue

            # verify and collect connected links
            for link, linfo in dinfo.interfaces.items():
                if "reserved" in linfo:
                    self._debug2("Reserved link: {}/{}".format(dut, link))
                    reserved_links.append([dut, link, linfo])
                    continue
                EndDevice = linfo.get("EndDevice", "")
                if not EndDevice:
                    unconnected_links.append([dut, link, linfo])
                    continue
                if "EndDevice" not in linfo:
                    msg = "EndDevice is not specified for interface {}/{}".format(dut, link)
                    self.set_validity(msg)
                    continue
                EndPort = linfo.get("EndPort", "")
                if not EndPort:
                    msg = "EndPort is not specified for interface {}/{}".format(dut, link)
                    self.logger.error(msg)
                    self.set_validity(msg)
                    continue
                EndDevice = self.device_name_map.get(linfo.EndDevice)
                if EndDevice not in self.devices:
                    msg = "EndDevice {} is not found".format(EndDevice)
                    self.logger.error(msg)
                    self.set_validity(msg)
                    continue
                if self._is_ignored_device(EndDevice):
                    self._debug("EndDevice {} is reserved ignoring {}/{}".format(EndDevice, dut, link))
                    reserved_links.append([dut, link, linfo])
                    continue

                # support range format for links
                incr = linfo.get("incr", "1")
                end_ports = self.expand_range(EndPort, incr)
                if len(end_ports) > 1:
                    from_ports = self.expand_range(link, incr)
                else:
                    from_ports = [link]
                for index, (from_port, end_port) in enumerate(zip(from_ports, end_ports)):
                    linfo2 = copy.deepcopy(linfo)
                    linfo2.EndPort = end_port
                    connected_links.append([dut, from_port, linfo2])

                if EndDevice not in profile.topology.devices:
                    add_devices.append(EndDevice)
            del profile.topology.devices[dut]["interfaces"]

        for dut, dinfo in profile.topology.devices.items():
            if dut not in self.devices:
                msg = "Device {} is not present in devices section".format(dut)
                self.logger.error(msg)
                self.set_validity(msg)
                return False
            else:
                if dinfo:
                    props = dinfo.get("properties", None)
                else:
                    props = dict()
                profile.topology.devices[dut] = self.devices[dut]
                if props:
                    profile.topology.devices[dut]["topo_props"] = props

        for dut in add_devices:
            profile.topology.devices[dut] = self.devices[dut]
        # utils.print_data(profile.topology, "topology-2")

        # add DUT internal name
        dut_index = tg_index = 1
        for dut, dinfo in profile.topology.devices.items():
            dinfo["type"] = "DUT" if self.devices[dut].device_type != "TGEN" else "TG"
            if dinfo["type"] == "DUT":
                if self.offset is None:
                    dinfo["__name__"] = dut
                else:
                    dinfo["__name__"] = "D{}".format(dut_index + self.offset)
                dinfo["__name0__"] = "D{}".format(dut_index)
                dinfo.alias = dut
                dut_index += 1
            elif dinfo["type"] == "TG":
                if self.offset is None:
                    dinfo["__name__"] = dut
                else:
                    dinfo["__name__"] = "T{}".format(tg_index + self.offset)
                dinfo["__name0__"] = "T{}".format(tg_index)
                dinfo.alias = dut
                tg_index += 1
        # utils.print_yaml(profile.topology, "topology-4")

        for dut, link, linfo in reserved_links:
            ent = SpyTestDict({
                "from_port": link, "from_dut": self.devices[dut].__name__
            })
            link_name = "{}-{}".format(ent.from_dut, ent.from_port)
            profile.reserved_links[link_name] = ent
        # utils.print_yaml(profile.reserved_links, "reserved_links")

        for dut, link, linfo in unconnected_links:
            ent = SpyTestDict({
                "from_port": link, "from_dut": self.devices[dut].__name__
            })
            exclude = ["EndDevice", "EndPort"]
            exclude.extend(ent.keys())
            utils.copy_items(linfo, ent, exclude=exclude)
            link_name = "{}-{}".format(ent.from_dut, ent.from_port)
            profile.unconnected_links[link_name] = ent
        # utils.print_yaml(profile.unconnected_links, "unconnected_links")

        profile.links.clear()
        for dut, link, linfo in connected_links:
            EndDevice = self.device_name_map.get(linfo.EndDevice)
            ent = SpyTestDict({
                "from_port": link, "from_dut": self.devices[dut].__name__,
                "to_port": linfo.EndPort, "to_dut": self.devices[EndDevice].__name__,
                "from_type": self.devices[dut].type,
                "to_type": self.devices[EndDevice].type,
            })
            exclude = ["EndDevice", "EndPort"]
            exclude.extend(ent.keys())
            utils.copy_items(linfo, ent, exclude=exclude)
            link_name = "{}-{}-{}-{}".format(ent.from_dut, ent.from_port,
                                             ent.to_dut, ent.to_port)

            # if what is added is duplicate
            ent = SpyTestDict({
                "to_port": link, "to_dut": self.devices[dut].__name__,
                "from_port": linfo.EndPort, "from_dut": self.devices[EndDevice].__name__,
                "to_type": self.devices[dut].type,
                "from_type": self.devices[EndDevice].type,
            })
            exclude = ["EndDevice", "EndPort"]
            exclude.extend(ent.keys())
            utils.copy_items(linfo, ent, exclude=exclude)
            link_name2 = "{}-{}-{}-{}".format(ent.from_dut, ent.from_port,
                                              ent.to_dut, ent.to_port)
            if link_name2 not in profile.links:
                profile.links[link_name] = ent
            else:
                self._debug2("Ignoring duplicate link {} existing {}".format(link_name, link_name2))

        # add link name variables
        link_indexes = SpyTestDict()
        for link_name, linfo in profile.links.items():
            from_dev = self.get_device_info(linfo.from_dut, linfo.from_type)
            to_dev = self.get_device_info(linfo.to_dut, linfo.to_type)
            index_key1 = "{}{}".format(linfo.from_dut, linfo.to_dut)
            index_key2 = "{}{}".format(linfo.to_dut, linfo.from_dut)
            index_key3 = "{}{}".format(from_dev.__name0__, to_dev.__name0__)
            index_key4 = "{}{}".format(to_dev.__name0__, from_dev.__name0__)
            index_key = index_key2 if linfo.to_dut < linfo.from_dut else index_key1
            index = 1 if index_key not in link_indexes else link_indexes[index_key] + 1
            link_indexes[index_key] = index
            linfo.__name1__ = "{}P{}".format(index_key1, index)
            linfo.__name2__ = "{}P{}".format(index_key2, index)
            linfo.__name3__ = "{}P{}".format(index_key3, index)
            linfo.__name4__ = "{}P{}".format(index_key4, index)
            index += 1
        return True

    def expand_range(self, value, incr=1):
        retval, prefix = [], "Ethernet"
        if "-" not in value or not value.startswith(prefix):
            return value.split(",")
        port_range = value.replace(prefix, "").split("-")
        for i in range(int(port_range[0]), int(port_range[1]) + 1, int(incr)):
            retval.append("{}{}".format(prefix, i))
        return retval

    def _override_sections(self, change_sections):
        if not change_sections:
            return
        for k, v in change_sections:
            if v in self.oyaml_data:
                self.oyaml_data[k] = self.oyaml_data[v]
                msg = "Override Section {} with {}".format(k, v)
            else:
                msg = "Missing Section {} to override {}".format(v, k)
            self.logger.warning(msg)

    def _override_section_values(self, change_section_values):
        if not change_section_values:
            return
        for k, v in change_section_values:
            if not k:
                continue
            node, parts = self.oyaml_data, k.split("/")
            for part in parts[:-1]:
                node = node.get(part, SpyTestDict())
            node[parts[-1]] = v
            msg = "Override Section {} with {}".format(k, v)
            self.logger.warning(msg)

    def _override_values(self, src, dst):
        for name, value in src.items():
            if name not in dst:
                dst.name = value
                # print("add new tree {} - {}".format(name, value))
            elif isinstance(dst[name], dict):
                # print("update tree {} - {}".format(name, value))
                self._override_values(value, dst[name])
            elif isinstance(dst[name], list):
                print("TODO list update {} - {}".format(name, value))
                # import pdb;pdb.set_trace()
            else:
                # print("leaf {} - {}".format(name, value))
                dst[name] = value

    def _load_yaml(self, filename):
        errs = []
        try:
            user_root = env.get("SPYTEST_USER_ROOT")
            if user_root:
                self.oyaml = OrderedYaml(filename, [user_root, testbeds_root])
            else:
                self.oyaml = OrderedYaml(filename, [testbeds_root])
            if not self.oyaml.is_valid():
                errs = self.oyaml.get_errors()
                self.logger.error(errs)
                return False
            obj = self.oyaml_data = self.oyaml.get_data()
            self.oyaml_data_copy = copy.deepcopy(obj)

            # override section names and values
            if self.cfg and self.cfg.change_section:
                self._override_sections(self.cfg.change_section)
            if self.cfg and self.cfg.change_section_value:
                self._override_section_values(self.cfg.change_section_value)

            # utils.print_yaml(obj, "TESTBED FILE CONTENT")
            if "devices" not in obj:
                errs.append("devices not found")
            if "services" not in obj:
                errs.append("services not found")
            if "configs" not in obj:
                errs.append("configs not found")
            if "builds" not in obj:
                errs.append("builds not found")
            if "params" not in obj:
                errs.append("params not found")
            if "topology" not in obj and "topologies" not in obj:
                errs.append("{} or {} not found".format("topology", "topologies"))
            if errs:
                errs.insert(0, "Invalid testbed file: " + filename)
                raise ValueError(" ".join(errs))
            if "global" in obj and "params" in obj["global"]:
                self.global_params = obj["global"]["params"]

            self.name = obj.get("name", "unknown")
            self.overrides = obj.get("overrides", self.overrides)
            self._override_values(self.overrides, obj)
            self.devices = obj["devices"]
            self.services = obj["services"]
            self.configs = obj["configs"]
            self.builds = obj["builds"]

            if "errors" not in obj:
                self.logger.warning("errors section not found - using defaults")
            else:
                self.errors = obj["errors"]
            if "speeds" not in obj:
                self.logger.warning("speeds section not found")
            else:
                self.speeds = obj["speeds"]
            if "instrument" not in obj:
                self._debug("instrument section not found")
            else:
                self.instrument = obj["instrument"]
            self.params = obj["params"]
            if "topologies" not in obj:
                self.topologies = SpyTestDict()
                if not obj["topology"]:
                    first_dev = list(obj["devices"].keys())[0]
                    obj["topology"] = SpyTestDict([(first_dev, None)])
                self.topologies[self.defaut_topo_index] = obj["topology"]
            else:
                self.topologies = obj["topologies"]
                if "topology" in obj and self.defaut_topo_index not in self.topologies:
                    self.topologies[self.defaut_topo_index] = obj["topology"]
            self.colors = SpyTestDict()
            try:
                self.colors.free = obj["colors"]["free"]
                self.colors.used = obj["colors"]["used"]
                assert (isinstance(self.colors.used, list))
                assert (isinstance(self.colors.free, str))
            except Exception:
                self.colors.free = None
                self.colors.used = ["red"]

            for profile in self.get_all_profiles():
                self._init_topology(profile)
            return True

        except Exception:
            self.topologies = SpyTestDict()
            self.devices = None
            self.services = None
            self.configs = None
            self.builds = None
            self.errors = None
            self.speeds = None
            self.instrument = None
            self.params = None
            errs = utils.stack_trace(None, True)
            errs.insert(0, "Invalid testbed file:: " + filename)
            self.logger.error("\n".join(errs))
        return False

    def _init_topology(self, profile):

        self.set_topo_index(profile.index)

        # read topology children
        profile.topology = profile.topology or SpyTestDict()
        properties = profile.topology.get("properties", SpyTestDict())
        devices = profile.topology.get("devices", SpyTestDict())
        if "devices" not in profile.topology:
            for k, v in profile.topology.items():
                devices[k] = v
        profile.topology.clear()
        if properties:
            profile.topology.properties = properties
        profile.topology.devices = devices

        # init breakout from devices and topology devices
        for d, dinfo in self.devices.items():
            profile.breakout.setdefault(d, SpyTestDict())
            for port, option in dinfo.get("breakout", SpyTestDict()).items():
                profile.breakout[d][port] = option
        for d, dinfo in profile.topology.devices.items():
            if dinfo:
                profile.breakout.setdefault(d, SpyTestDict())
                for port, option in dinfo.get("breakout", SpyTestDict()).items():
                    profile.breakout[d][port] = option

        # build device name map
        self.device_name_map.clear()
        for device in self.devices:
            self.device_name_map[device] = device

        # rename the devices
        if self.rename_devices:
            devices, topo_devices = SpyTestDict(), SpyTestDict()
            for entry in self.rename_devices:
                old, new = entry.split(":")
                self.device_name_map[old] = new
            for device, dinfo in profile.topology.devices.items():
                topo_devices[self.device_name_map[device]] = dinfo
            profile.topology.devices = topo_devices
            for device, dinfo in self.devices.items():
                devices[self.device_name_map[device]] = dinfo
            self.devices = devices

        # reorder the devices
        if self.reorder_devices:
            devices, topo_devices = SpyTestDict(), SpyTestDict()
            for index, device in enumerate(profile.topology.devices.keys()):
                dinfo = profile.topology.devices[device]
                if index < len(self.reorder_devices):
                    value = self.reorder_devices[index]
                    if value not in self.devices:
                        msg = "reorder device {} is invalid".format(value)
                        self.logger.error(msg)
                    elif value in topo_devices:
                        msg = "reorder device {} is repeated".format(value)
                        self.logger.error(msg)
                    else:
                        device = value
                topo_devices[device] = dinfo
            profile.topology.devices = topo_devices
            for index, device in enumerate(self.devices.keys()):
                dinfo = self.devices[device]
                if index < len(self.reorder_devices):
                    value = self.reorder_devices[index]
                    if value not in self.devices:
                        msg = "reorder device {} is invalid".format(value)
                        self.logger.error(msg)
                    elif value in devices:
                        msg = "reorder device {} is repeated".format(value)
                        self.logger.error(msg)
                    else:
                        device = value
                devices[device] = dinfo
            self.devices = devices

        # override device properties from command line
        if self.cfg and self.cfg.dev_prop:
            for d, k, v in self.cfg.dev_prop:
                for devname, dinfo in self.devices.items():
                    if "properties" not in dinfo:
                        dinfo.properties = SpyTestDict()
                    if d == "__all__" or d == devname:
                        dinfo.properties[k] = v

        # override device parameters from command line
        self._override_dev_params()

        # override ixnetwork from command line
        if self.cfg and self.cfg.ixserver:
            ix_server = ",".join(self.cfg.ixserver)
            for dinfo in self.devices.values():
                if dinfo.device_type == "TGEN" and dinfo.properties:
                    dinfo.properties["ix_server"] = ix_server

    def get_device_property(self, dut, prop, default=None):
        profile = self.get_profile()
        for d, dinfo in profile.topology.devices.items():
            if dinfo["__name__"] != dut:
                continue
            if "properties" not in dinfo:
                msg = "properties not availbale for {}".format(d)
                self.logger.info(msg)
                return None
            if prop in dinfo.properties:
                return dinfo.properties[prop]
            if not default:
                self._debug2("'{}' not set in properties for {}".format(prop, d))
                return None
            msg = "'{}' not set in properties for {} assuming '{}'".format(prop, d, default)
            if prop != "instrument":
                self._debug(msg)
            return default

    def _get_dut_property(self, dut, prop, table, subprop, defprop=None):
        ref = self.get_device_property(dut, prop, defprop)
        if not ref:
            return None
        table_object = getattr(self, table)
        if not table_object or ref not in table_object:
            self._debug("{}/{} is not found".format(table, ref))
            return None
        if not subprop or not table_object[ref]:
            return table_object[ref]
        if subprop not in table_object[ref]:
            self._debug("{} is not specified in {}/{}".format(subprop, table, ref))
            return None
        return table_object[ref][subprop]

    def _get_dut_property_old(self, dut, prop, table, subprop, defprop=None):
        profile = self.get_profile()
        for d, dinfo in profile.topology.devices.items():
            if dinfo["__name__"] == dut:
                if "properties" not in dinfo:
                    msg = "properties not availbale for {}".format(d)
                    self.logger.info(msg)
                    return None
                if prop not in dinfo.properties:
                    if not defprop:
                        self._debug2("'{}' not set in properties for {}".format(prop, d))
                        return None
                    msg = "'{}' not set in properties for {} assuming '{}'".format(prop, d, defprop)
                    if prop != "instrument":
                        self._debug(msg)
                    ref = defprop
                else:
                    ref = dinfo.properties[prop]
                table_object = getattr(self, table)
                if not table_object or ref not in table_object:
                    self._debug("{}/{} is not found".format(table, ref))
                    return None
                if not subprop or not table_object[ref]:
                    return table_object[ref]
                if subprop not in table_object[ref]:
                    self._debug("{} is not specified in {}/{}".format(subprop, table, ref))
                    return None
                return table_object[ref][subprop]
        return None

    def get_dut_label(self, dut):
        profile = self.get_profile()
        for dinfo in profile.topology.devices.values():
            if dinfo.__name__ == dut or dinfo.__name0__ == dut:
                if dinfo.__name0__ == dinfo.alias:
                    return dinfo.__name0__
                return "{}-{}".format(dinfo.__name0__, dinfo.alias)
        return dut

    def get_device_type(self, dut, default="sonic"):
        dinfo = self.get_device_info(dut)
        if not dinfo:
            return default
        if dinfo.device_type in ["DevSonic"]:
            return "sonic"
        return dinfo.device_type

    def get_service(self, dut, name):
        return self._get_dut_property(dut, "services", "services", name)

    def get_config(self, dut, scope):
        return self._get_dut_property(dut, "config", "configs", scope)

    def get_config_file_path(self, file_name):
        return self._locate(file_name)

    def get_build(self, dut, scope):
        return self._get_dut_property(dut, "build", "builds", scope)

    def get_error(self, dut, scope):
        return self._get_dut_property(dut, "errors", "errors", scope, "default")

    def get_speed(self, dut, scope=None):
        rv = self._get_dut_property(dut, "speed", "speeds", scope, None)
        if not rv:
            rv = SpyTestDict()
        for local, _, _ in self.get_links(dut):
            value = self.get_link_param(dut, local, "speed", None)
            if value:
                rv[local] = value
        return rv

    def get_instrument(self, dut, scope=None):
        return self._get_dut_property(dut, "instrument", "instrument", scope, "default")

    def get_param(self, name, default):
        if not self.global_params:
            return default
        if not name:
            return self.global_params
        if name not in self.global_params:
            return default
        return self.global_params[name]

    def get_device_param(self, dut, name, default):
        profile = self.get_profile()
        for d, dinfo in profile.topology.devices.items():
            if dinfo["__name__"] == dut:

                # check for per dut params override
                if "params" in dinfo and name in dinfo.params:
                    return dinfo.params[name]

                if "properties" not in dinfo:
                    self._debug("properties not availbale for {}".format(d))
                    return default

                if "params" not in dinfo.properties:
                    self._debug2("params not set in properties for {}".format(d))
                    return default

                ref = dinfo.properties.params
                if ref not in self.params:
                    self._debug("params {} not found".format(ref))
                    return default
                if not name:
                    return self.params[ref]
                if name not in self.params[ref]:
                    return default
                return self.params[ref][name]
        return default

    def _get_link_param(self, dut, link, linfo, name):

        # see if there is parameter override
        if name in linfo:
            return linfo[name]

        if "params" not in linfo or linfo.params is None:
            self._debug2("params not set in properties for {}".format(link))
            return None

        ref = linfo.params
        if ref not in self.params:
            self._debug("params {} not found".format(ref))
            return None

        if not name:
            return self.params[ref]

        if name not in self.params[ref]:
            return None

        return self.params[ref][name]

    def get_link_param(self, dut, local, name, default):
        profile = self.get_profile()
        for link, linfo in profile.links.items():
            if linfo["from_dut"] == dut and linfo["from_port"] == local:
                pass
            elif linfo["to_dut"] == dut and linfo["to_port"] == local:
                pass
            else:
                continue
            rv = self._get_link_param(dut, link, linfo, name)
            if rv is not None:
                return rv
        return default

    def get_breakout(self, dut, portList=None, section=None):
        retval = []

        # verify if the dut is valid
        dinfo = self.get_device_info(dut)
        if not dinfo:
            return retval

        # check if port list given for matching
        if portList is None:
            match_ports = None
        else:
            match_ports = utils.make_list(portList)

        # init breakout dictionary
        bod = SpyTestDict()

        # read breakout from devices section
        breakout = dinfo.get(section or "breakout")
        if breakout:
            for port, option in breakout.items():
                bod[port] = option

        # override breakout from topology breakout section
        profile = self.get_profile()
        for port, option in profile.breakout.get(dut, {}).items():
            bod[port] = option

        # override breakout from topology interfaces section
        for port, _, _ in self.get_links(dut):
            option = self.get_link_param(dut, port, "breakout", None)
            if option is not None:
                bod[port] = option

        for link, linfo in profile.unconnected_links.items():
            if dut in [linfo.from_dut]:
                option = self._get_link_param(dut, link, linfo, "breakout")
                if option is not None:
                    bod[linfo.from_port] = option

        # filter results
        for port, option in bod.items():
            if match_ports is None:
                retval.append([port, option])
            elif port in match_ports:
                retval.append([port, option])

        return retval

    def get_profile(self, index=None):
        retval = SpyTestDict()
        if index is None:
            index = self.current_topo_index
        retval.topology = self.topologies.setdefault(index, SpyTestDict())
        retval.breakout = self.all_breakouts.setdefault(index, SpyTestDict())
        retval.links = self.all_links.setdefault(index, SpyTestDict())
        retval.reserved_links = self.all_reserved_links.setdefault(index, SpyTestDict())
        retval.unconnected_links = self.all_unconnected_links.setdefault(index, SpyTestDict())
        retval.index = index
        return retval

    def get_all_profiles(self):
        retval = []
        for index in self.topologies:
            retval.append(self.get_profile(index))
        return retval

    def set_topo_index(self, index):
        if index >= len(self.topologies):
            return False
        self.current_topo_index = index
        return True

    def get_name(self):
        return self.name

    def get_device_names(self, dtype=None):
        """
        Returns names of all devices of given type
        :return: device names of given type
        :rtype: list
        """
        retval = []
        if self.flex_dut and self.derived.duts:
            if dtype == "DUT":
                return self.derived.duts
            if dtype is None:
                retval.extend(self.derived.duts)
                dtype = "TG"
        profile = self.get_profile()
        topo_devices = profile.topology.get("devices", {})
        for dinfo in topo_devices.values():
            if not dtype or dinfo["type"] == dtype:
                name = dinfo["__name__"]
                if name not in retval:
                    retval.append(name)
        return retval

    def get_devices_info(self, dtype=None):
        retval = {}
        for dut in self.get_device_names(dtype):
            chip = self.get_device_param(dut, "chip", "UNKNOWN")
            chip_rev = self.get_device_param(dut, "chip_rev", "UNKNOWN")
            chip_disp = chip
            if chip and chip_rev and chip_rev not in ["NA", "UNKNOWN"]:
                chip_disp = "{}-{}".format(chip, chip_rev)
            retval[dut] = {
                "chip": chip, "chip_rev": chip_rev, "chip_disp": chip_disp,
                "name": dut, "type": self.get_device_type(dut, 'UNKNOWN'),
                "model": self.get_device_param(dut, "model", 'UNKNOWN')
            }
            for index in range(1, Testbed.max_dut_models):
                pname = "model{}".format(index)
                retval[dut][pname] = self.get_device_param(dut, pname, "UNKNOWN")
        return retval

    def get_device_types(self, dtype=None):
        retval = []
        for dut in self.get_device_names(dtype):
            value = self.get_device_type(dut, 'UNKNOWN')
            retval.append(value)
        return retval

    def get_device_models(self, dtype=None):
        retval = []
        for dut in self.get_device_names(dtype):
            model = self.get_device_param(dut, "model", 'UNKNOWN')
            retval.append(model)
        return retval

    def get_device_chips(self, dtype=None):
        retval = []
        for dut in self.get_device_names(dtype):
            chip = self.get_device_param(dut, "chip", None)
            if chip:
                chip_rev = self.get_device_param(dut, "chip_rev", None)
                if chip_rev:
                    chip = "{}-{}".format(chip, chip_rev)
            retval.append(chip or "UNKNOWN")
        return retval

    def get_tgen_types(self):
        retval = []
        for dev in self.get_device_names("TG"):
            tinfo = self.get_tg_info(dev)
            retval.append(tinfo["type"])
        return retval

    def get_rerved_links(self, dut):
        retval, profile = [], self.get_profile()
        for linfo in profile.reserved_links.values():
            if linfo["from_dut"] == dut:
                retval.append(linfo["from_port"])
        return retval

    def _build_link(self, link, linfo, rev, name=False, ifmap=None, native_map=None):
        native_map = native_map or {}
        ifmap = ifmap or {}
        if rev:
            rv = [linfo["to_port"], linfo["from_dut"], linfo["from_port"]]
            if linfo["to_type"] == "DUT":
                rv[0] = self.map_port_name(linfo["to_dut"], linfo["to_port"], ifmap, native_map)
            if linfo["from_type"] == "DUT":
                rv[2] = self.map_port_name(linfo["from_dut"], linfo["from_port"], ifmap, native_map)
        else:
            rv = [linfo["from_port"], linfo["to_dut"], linfo["to_port"]]
            if linfo["from_type"] == "DUT":
                rv[0] = self.map_port_name(linfo["from_dut"], linfo["from_port"], ifmap, native_map)
            if linfo["to_type"] == "DUT":
                rv[2] = self.map_port_name(linfo["to_dut"], linfo["to_port"], ifmap, native_map)
        if name:
            rv.append(link)
        return rv

    def _is_valid_dut(self, dut, dtype):
        if not self.flex_dut or dtype == 'TG':
            return True
        if not self.derived.duts:
            return True
        if dut in self.derived.duts:
            return True
        return False

    def _is_valid_port(self, from_dut, from_port, to_dut, to_port):
        if not self.flex_port:
            return True
        if not self.derived.down_ports:
            return True
        if from_dut in self.derived.down_ports:
            if from_port in self.derived.down_ports[from_dut]:
                return False
        if to_dut in self.derived.down_ports:
            if to_port in self.derived.down_ports[to_dut]:
                return False
        return True

    def get_links(self, dut, peer=None, dtype=None, name=False, ifmap=None, native_map=None):
        ifmap = ifmap or {}
        native_map = native_map or {}
        retval = []
        profile = self.get_profile()
        for link, linfo in profile.links.items():
            from_type, to_type = linfo["from_type"], linfo["to_type"]
            from_dut, to_dut = linfo["from_dut"], linfo["to_dut"]
            from_port, to_port = linfo["from_port"], linfo["to_port"]
            if peer:
                if from_dut == dut and to_dut == peer:
                    if not dtype or dtype == to_type:
                        if not self._is_valid_dut(to_dut, to_type):
                            continue
                        if not self._is_valid_port(from_dut, from_port, to_dut, to_port):
                            continue
                        retval.append(self._build_link(link, linfo, False, name, ifmap, native_map))
                if to_dut == dut and from_dut == peer:
                    if not dtype or dtype == from_type:
                        if not self._is_valid_dut(from_dut, from_type):
                            continue
                        if not self._is_valid_port(from_dut, from_port, to_dut, to_port):
                            continue
                        retval.append(self._build_link(link, linfo, True, name, ifmap, native_map))
            else:
                if from_dut == dut:
                    if not dtype or dtype == to_type:
                        if not self._is_valid_dut(to_dut, to_type):
                            continue
                        if not self._is_valid_port(from_dut, from_port, to_dut, to_port):
                            continue
                        retval.append(self._build_link(link, linfo, False, name, ifmap, native_map))
                if to_dut == dut:
                    if not dtype or dtype == from_type:
                        if not self._is_valid_dut(from_dut, from_type):
                            continue
                        if not self._is_valid_port(from_dut, from_port, to_dut, to_port):
                            continue
                        retval.append(self._build_link(link, linfo, True, name, ifmap, native_map))
        return retval

    def get_tg_info(self, tg):
        """
        Get the properties of given TGEN device
        :param tg: Name of the TGEN device
        :type tg: string
        :return: properties dictionary
        :rtype: dict
        """
        profile = self.get_profile()
        for dinfo in profile.topology.devices.values():
            if dinfo.type == "TG":
                if not tg or dinfo["__name__"] == tg:
                    rv = SpyTestDict()
                    rv.name = dinfo.__name__
                    rv.ip = dinfo.properties.ip
                    rv.type = dinfo.properties.type
                    rv.virtual = bool(dinfo.properties.get("virtual", 0))
                    rv.version = dinfo.properties.version
                    rv.card = getattr(dinfo.properties, "card", "")
                    rv.speed = getattr(dinfo.properties, "speed", "")
                    rv.config_file = getattr(dinfo.properties, "config_file", "")
                    rv.port_speed = getattr(dinfo.properties, "port_speed", "")
                    rv.auto_neg = getattr(dinfo.properties, "auto_neg", 0)
                    rv.phy_mode = getattr(dinfo.properties, "phy_mode", "")
                    rv.fec = getattr(dinfo.properties, "fec", 0)
                    if "ix_server" in dinfo.properties:
                        rv.ix_server = dinfo.properties.ix_server
                    if "ix_port" in dinfo.properties:
                        rv.ix_port = dinfo.properties.ix_port
                    return rv
        return None

    def get_ts(self, dut):
        """
        Returns Terminal Server details read from testbed file for given DUT
        :param dut: DUT identifier
        :type dut: basestring
        :return: Terminal Server parameters dictionary
        :rtype: dict
        """
        rv = self.get_device_info(dut)
        if rv and "ts" in rv:
            return rv["ts"]
        return None

    def get_rps(self, dut):
        """
        Returns RPS details read from testbed file for given DUT
        :param dut: DUT identifier
        :type dut: basestring
        :return: RPS parameters dictionary
        :rtype: dict
        """
        rv = []
        dinfo = self.get_device_info(dut)
        for key in ["rps", "rps1", "rps2"]:
            if dinfo and key in dinfo:
                rv.append(dinfo[key])
        return rv

    @staticmethod
    def map_port_name(dut, port, ifmap=None, native_map=None):
        if ifmap is None or native_map is None:
            return port
        if dut not in native_map or native_map[dut]:
            return port
        if dut not in ifmap or port not in ifmap[dut]:
            return port
        return ifmap[dut][port]

    def get_testbed_vars(self, ifmap=None, native_map=None):
        """
        returns the testbed variables in a dictionary
        :return: testbed variables dictionary
        :rtype: dict
        """
        rv = SpyTestDict()
        rv.tgen_list = self.get_device_names("TG")
        rv.tgen_ports = SpyTestDict()
        rv.dut_list = self.get_device_names("DUT")
        rv.dut_ids = SpyTestDict()
        dut_index = 1
        for dut in rv.dut_list:
            dut_name = "D{}".format(dut_index)
            rv[dut_name] = dut
            rv.dut_ids[dut] = dut_name
            dut_index = dut_index + 1
        tg_index = 1
        tg_types = dict()
        for tg in rv.tgen_list:
            tg_info = self.get_tg_info(tg)
            tg_name = "T{}".format(tg_index)
            tg_types[tg_name] = tg_info.type
            rv[tg_name] = tg
            tg_index = tg_index + 1
        for from_index in range(1, dut_index):
            for to_index in range(from_index + 1, dut_index):
                from_name = "D{}".format(from_index)
                to_name = "D{}".format(to_index)
                (from_dev, to_dev) = (rv[from_name], rv[to_name])
                links = self.get_links(from_dev, to_dev)
                lnum = 1
                for local, _, remote in links:
                    lname1 = "{}{}P{}".format(from_name, to_name, lnum)
                    lname2 = "{}{}P{}".format(to_name, from_name, lnum)
                    lnum = lnum + 1
                    rv[lname1] = self.map_port_name(from_dev, local, ifmap, native_map)
                    rv[lname2] = self.map_port_name(to_dev, remote, ifmap, native_map)
        if self.common_tgen_ports:
            for to_index in range(1, dut_index):
                lnum = 1
                for from_index in range(1, tg_index):
                    from_name = "T{}".format(from_index)
                    to_name = "D{}".format(to_index)
                    (from_dev, to_dev) = (rv[from_name], rv[to_name])
                    links = self.get_links(from_dev, to_dev)
                    for local, _, remote in links:
                        lname1 = "T1{}P{}".format(to_name, lnum)
                        lname2 = "{}T1P{}".format(to_name, lnum)
                        lnum = lnum + 1
                        rv[lname1] = local
                        rv[lname2] = self.map_port_name(to_dev, remote, ifmap, native_map)
                        rv.tgen_ports[lname1] = [from_name, tg_types[from_name], local]
        else:
            for from_index in range(1, tg_index):
                for to_index in range(1, dut_index):
                    from_name = "T{}".format(from_index)
                    to_name = "D{}".format(to_index)
                    (from_dev, to_dev) = (rv[from_name], rv[to_name])
                    links = self.get_links(from_dev, to_dev)
                    lnum = 1
                    for local, _, remote in links:
                        lname1 = "{}{}P{}".format(from_name, to_name, lnum)
                        lname2 = "{}{}P{}".format(to_name, from_name, lnum)
                        lnum = lnum + 1
                        rv[lname1] = local
                        rv[lname2] = self.map_port_name(to_dev, remote, ifmap, native_map)
                        rv.tgen_ports[lname1] = [from_name, tg_types[from_name], local]

        return rv

    def get_access(self, string=True):
        retval, profile = [], self.get_profile()
        for dut, dinfo in profile.topology.devices.items():
            if dinfo["type"] != "DUT":
                continue
            retval.append("{} {} {} {} {} {} {}".format(dut,
                                                        dinfo.access.protocol,
                                                        dinfo.access.ip,
                                                        dinfo.access.port,
                                                        dinfo.credentials.username,
                                                        dinfo.credentials.password,
                                                        dinfo.credentials.altpassword))
        return "\n".join(retval) if string else retval

    def get_topo(self, name0=True, props=False):
        retval, exclude = [], []
        for dut in self.get_device_names():
            dinfo = self.get_device_info(dut)
            dname = dinfo.__name0__ if name0 else dinfo.__name__
            partners = OrderedDict()
            for _, partner, _ in self.get_links(dut):
                partners[partner] = partners.setdefault(partner, 0) + 1
            for partner in partners:
                if "{}--{}".format(dut, partner) in exclude:
                    continue
                exclude.append("{}--{}".format(partner, dut))
                pdinfo = self.get_device_info(partner)
                pdname = pdinfo.__name0__ if name0 else pdinfo.__name__
                retval.append("{}{}:{}".format(dname, pdname, partners[partner]))
            if not partners:
                retval.append("{}".format(dname))
            if props:
                for index in range(Testbed.max_dut_models):
                    pname = "model" if not index else "model{}".format(index)
                    pval = self.get_device_param(dut, pname, None)
                    if pval:
                        retval.append("{}{}:{}".format(dname, pname.upper(), pval))
        return ",".join(retval) if retval else "D1"

    def _check_min_links(self, from_type, to_type, res, errs):
        from_dev = self.get_device_name("{}{}".format(from_type, res.group(1)))
        to_dev = self.get_device_name("{}{}".format(to_type, res.group(2)))
        if not from_dev:
            errs.append("no_dut")
            return [False, from_dev, to_dev]
        if int(res.group(3)) != 0 and not to_dev:
            errs.append("no_dut")
            return [False, from_dev, to_dev]
        links = self.get_links(from_dev, to_dev)
        if len(links) < int(res.group(3)):
            errs.append("no_link")
            return [False, from_dev, to_dev]

        return [True, from_dev, to_dev]

    @staticmethod
    def _split_args(*args):
        sep = env.get("SPYTEST_TOPO_SEP")
        arg_list = []
        for arg in args:
            arg_list.extend(utils.split_byall(arg, sep=sep))
        return arg_list

    @staticmethod
    def parse_topology(*args):
        requests = []
        properties = dict()
        errs = []
        arg_list = Testbed._split_args(*args)
        for arg in arg_list:
            if arg == "D1":
                arg = "D1T1:0"
            if re.compile(r"^D\d+$").match(arg):
                res = re.search(r"^D(\d+)$", arg)
                arg = "D{}T1:0".format(res.group(1))
            if re.compile(r"^D\d+D\d+:\d+$").match(arg):
                res = re.search(r"^D(\d+)D(\d+):(\d+)$", arg)
                if int(res.group(1)) == int(res.group(2)):
                    errs.append("{}: invalid".format(arg))
                    continue
                requests.append(["D", "D", res, arg])
            elif re.compile(r"^D\d+T\d+:\d+$").match(arg):
                res = re.search(r"^D(\d+)T(\d+):(\d+)$", arg)
                requests.append(["D", "T", res, arg])
            elif re.compile(r"^T\d+D\d+:\d+$").match(arg):
                res = re.search(r"^T(\d+)D(\d+):(\d+)$", arg)
                requests.append(["T", "D", res, arg])
            elif re.compile(r"^D\d+BUILD[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)BUILD[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["BUILD"] = res.group(2)
            elif re.compile(r"^D\d+CONFIG[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)CONFIG[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["CONFIG"] = res.group(2)
            elif re.compile(r"^D\d+MODEL[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)MODEL[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["MODEL"] = res.group(2)
            elif re.compile(r"^D\d+MODEL\d+[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)MODEL(\d+)[:=](\S+)$", arg)
                model_number = int(res.group(2))
                if not model_number or model_number >= Testbed.max_dut_models:
                    errs.append("{}: unsupported".format(arg))
                    requests.append([None, None, 0, arg])
                else:
                    model_name = "MODEL{}".format(model_number)
                    properties.setdefault("D{}".format(res.group(1)), dict())[model_name] = res.group(3)
            elif re.compile(r"^D\d+CHIP[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)CHIP[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["CHIP"] = res.group(2)
            elif re.compile(r"^D\d+CHIP_REV[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)CHIP_REV[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["CHIP_REV"] = res.group(2)
            elif re.compile(r"^D\d+TYPE[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)TYPE[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["TYPE"] = res.group(2)
            elif re.compile(r"^D\d+NAME[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)NAME[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["NAME"] = res.group(2)
            elif re.compile(r"^D\d+UI[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)UI[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["UI"] = res.group(2)
            elif re.compile(r"^BUILD[:=]\S+$").match(arg):
                res = re.search(r"^BUILD[:=](\S+)$", arg)
                properties.setdefault(None, dict())["BUILD"] = res.group(1)
            elif re.compile(r"^CONFIG[:=]\S+$").match(arg):
                res = re.search(r"^CONFIG[:=](\S+)$", arg)
                properties.setdefault(None, dict())["CONFIG"] = res.group(1)
            elif re.compile(r"^MODEL[:=]\S+$").match(arg):
                res = re.search(r"^MODEL[:=](\S+)$", arg)
                properties.setdefault(None, dict())["MODEL"] = res.group(1)
            elif re.compile(r"^MODEL\d+[:=]\S+$").match(arg):
                res = re.search(r"^MODEL(\d+)[:=](\S+)$", arg)
                model_number = int(res.group(1))
                if not model_number or model_number >= Testbed.max_dut_models:
                    errs.append("{}:: unsupported".format(arg))
                    requests.append([None, None, 0, arg])
                else:
                    model_name = "MODEL{}".format(model_number)
                    properties.setdefault(None, dict())[model_name] = res.group(2)
            elif re.compile(r"^CHIP[:=]\S+$").match(arg):
                res = re.search(r"^CHIP[:=](\S+)$", arg)
                properties.setdefault(None, dict())["CHIP"] = res.group(1)
            elif re.compile(r"^CHIP_REV[:=]\S+$").match(arg):
                res = re.search(r"^CHIP_REV[:=](\S+)$", arg)
                properties.setdefault(None, dict())["CHIP_REV"] = res.group(1)
            elif re.compile(r"^TYPE[:=]\S+$").match(arg):
                res = re.search(r"^TYPE[:=](\S+)$", arg)
                properties.setdefault(None, dict())["TYPE"] = res.group(1)
            elif re.compile(r"^TGEN[:=]\S+$").match(arg):
                res = re.search(r"^TGEN[:=](\S+)$", arg)
                properties.setdefault(None, dict())["TGEN"] = res.group(1)
            elif re.compile(r"^NAME[:=]\S+$").match(arg):
                res = re.search(r"^NAME[:=](\S+)$", arg)
                properties.setdefault(None, dict())["NAME"] = res.group(1)
            elif re.compile(r"^UI[:=]\S+$").match(arg):
                res = re.search(r"^UI[:=](\S+)$", arg)
                properties.setdefault(None, dict())["UI"] = res.group(1)
            elif re.compile(r"^UNIQ[:=]\S+$").match(arg):
                res = re.search(r"^UNIQ[:=](\S+)$", arg)
                properties.setdefault(None, dict())["UNIQ"] = res.group(1)
            elif re.compile(r"^NAMES[:=]\S+$").match(arg):
                res = re.search(r"^NAMES[:=](\S+)$", arg)
                properties.setdefault(None, dict())["NAMES"] = res.group(1)
            elif re.compile(r"^CONSOLE_ONLY$").match(arg):
                properties.setdefault(None, dict())["CONSOLE_ONLY"] = True
            elif re.compile(r"^TGCARD[:=]\S+$").match(arg):
                res = re.search(r"^TGCARD[:=](\S+)$", arg)
                properties.setdefault(None, dict())["TGCARD"] = res.group(1)
            elif re.compile(r"^TGSPEED[:=]\S+$").match(arg):
                res = re.search(r"^TGSPEED[:=](\S+)$", arg)
                properties.setdefault(None, dict())["TGSPEED"] = res.group(1)
            elif re.compile(r"^SEARCH[:=]\S+$", re.IGNORECASE).match(arg):
                res = re.search(r"^SEARCH[:=](\S+)$", arg, re.IGNORECASE)
                properties.setdefault(None, dict())["SEARCH"] = res.group(1)
            elif re.compile(r"^COMMENT[:=]\S+$", re.IGNORECASE).match(arg):
                res = re.search(r"^COMMENT[:=](\S+)$", arg, re.IGNORECASE)
                properties.setdefault(None, dict())["COMMENT"] = res.group(1)
            elif re.compile(r"^POD[:=]\S+$", re.IGNORECASE).match(arg):
                res = re.search(r"^POD[:=](\S+)$", arg, re.IGNORECASE)
                properties.setdefault(None, dict())["POD"] = res.group(1)
            else:
                errs.append("{}::: unsupported".format(arg))
                requests.append([None, None, 0, arg])
        if errs:
            print("parse_topology--errors", errs)

        if not requests:
            res = re.search(r"^D(\d+)T(\d+):(\d+)$", "D1T1:0")
            requests.append(["D", "T", res, "D1T1:0"])

        return [requests, properties, errs]

    @staticmethod
    def ensure_tgen_model_and_card(logger, tb, properties, errs):

        tgens = tb.get_device_names("TG")
        l_errs = errs or []

        # check tg model requirements
        if "TG" not in tb.ignore_constraints:
            found = ""
            for tg in tgens:
                if properties.get("selected-tgen", tg) != tg:
                    continue
                if Testbed.check_tgen_model(logger, tb, tg, properties):
                    found = tg
                    break
                found = None
            if found is None:
                l_errs.append("no_tgen_model")
            else:
                properties.setdefault("selected-tgen", found)

        # check tg card requirements
        if "TGCARD" not in tb.ignore_constraints:
            found = ""
            for tg in tgens:
                if properties.get("selected-tgen", tg) != tg:
                    continue
                if Testbed.check_tgen_card(logger, tb, tg, properties):
                    found = tg
                    break
                found = None
            if found is None:
                l_errs.append("no_tgen_card")
            else:
                properties.setdefault("selected-tgen", found)

        # check tg speed requirements
        if "TGSPEED" not in tb.ignore_constraints:
            found = ""
            for tg in tgens:
                if properties.get("selected-tgen", tg) != tg:
                    continue
                if Testbed.check_tgen_speed(logger, tb, tg, properties):
                    found = tg
                    break
                found = None
            if found is None:
                l_errs.append("no_tgen_speed")
            else:
                properties.setdefault("selected-tgen", found)

        return l_errs

    def ensure_min_topology(self, *args, **kwargs):
        if env.get("SPYTEST_TESTBED_RANDOMIZE_DEVICES", "0") != "0":
            rv = self.ensure_min_topology_random(*args, **kwargs)
            if rv is not None:
                return rv
            # follow through to report the error
        return self.ensure_min_topology_norandom(*args, **kwargs)

    def ensure_min_topology_norandom(self, *args, **kwargs):
        [requests, properties, errs] = self.parse_topology(*args)
        if errs:
            return [errs, properties]

        debug = kwargs.get("debug", 0)
        logger = self.logger if debug else None

        # bailout if TG card/model is not satisfied
        errs = Testbed.ensure_tgen_model_and_card(logger, self, properties, [])
        if errs:
            return [errs, properties]

        topo_dinfo = OrderedDict()
        for from_type, to_type, res, arg in requests:
            if not from_type or not to_type:
                errs.append("no_dut")
                continue

            # check link requirements
            [rv, from_dev, to_dev] = self._check_min_links(from_type, to_type, res, errs)
            if not rv:
                errs.append(arg)
                continue

            # collect the devices info to match model name
            if properties and from_type == 'D':
                dinfo = self.get_device_info(from_dev)
                topo_dinfo[dinfo.__name0__] = dinfo
            if properties and to_type == 'D':
                dinfo = self.get_device_info(to_dev)
                topo_dinfo[dinfo.__name0__] = dinfo

        # check model requirements
        match_dut_model = kwargs.get("match_dut_model", 1)
        if match_dut_model and not errs:
            model_cache = {}
            for dut, dinfo in topo_dinfo.items():
                if not Testbed.check_model(logger, self, dut, dinfo.__name__, properties, model_cache):
                    if "MODEL" not in self.ignore_constraints:
                        errs.append("no_dut_model")

        # check chip requirements
        match_dut_chip = kwargs.get("match_dut_chip", 1)
        if match_dut_chip and not errs:
            for dut, dinfo in topo_dinfo.items():
                if not Testbed.check_chip(logger, self, dut, dinfo.__name__, properties):
                    if "CHIP" not in self.ignore_constraints:
                        errs.append("no_dut_chip")

        # check type requirements
        match_dut_type = kwargs.get("match_dut_type", 1)
        if match_dut_type and not errs:
            for dut, dinfo in topo_dinfo.items():
                if not Testbed.check_type(logger, self, dut, dinfo.__name__, properties):
                    if "TYPE" not in self.ignore_constraints:
                        errs.append("no_dut_type")

        # check if name is enforced
        match_dut_name = kwargs.get("match_dut_name", 0)
        if match_dut_name and not errs:
            for dut, dinfo in topo_dinfo.items():
                if not Testbed.check_dut_name(logger, self, dut, dinfo.__name__, properties):
                    errs.append("no_dut_name")

        # bail out on errors if not flex dut
        if not errs or not self.flex_dut:
            return [errs, properties]

        Testbed.trace2(logger, "------------ FLEX START --------------------")
        [setup_list, properties, _] = self.identify_topology(logger, self, None, 1, *args)
        Testbed.trace2(logger, "------------ FLEX END --------------------")
        if not setup_list:
            return [errs, properties]
        self.derived.duts = setup_list[0]
        return [[], properties]

    def ensure_min_topology_random(self, *args, **kwargs):
        debug = kwargs.get("debug", 0)
        logger = self.logger if debug else None

        [_, properties, errs] = self.parse_topology(*args)
        if errs:
            return [errs, properties]
        [setup_list, properties, _] = self.identify_topology_randomise(logger, self, None, 100, True, *args)
        if not setup_list:
            return None
        seed = utils.get_random_seed()
        Random(seed).shuffle(setup_list)
        self.derived.duts = setup_list[0]
        return [[], properties]

    def reset_derived(self):
        self.derived.duts = None
        self.derived.down_ports = None

    def set_port_down(self, dut, port):
        if not self.flex_port:
            return
        if not self.derived.down_ports:
            self.derived.down_ports = {}
        if dut not in self.derived.down_ports:
            self.derived.down_ports[dut] = []
        self.derived.down_ports[dut].append(port)

    @staticmethod
    def sort_topo_dict(topo_dict):
        topo_list = list(topo_dict.keys())
        ll = len(topo_list)
        for i in range(0, ll):
            for j in range(0, ll - i - 1):
                [a_from_dev, a_from_index, a_to_dev, a_to_index, _] = topo_dict.get(topo_list[j])
                [b_from_dev, b_from_index, b_to_dev, b_to_index, _] = topo_dict.get(topo_list[j + 1])
                if a_from_dev > b_from_dev or a_from_index > b_from_index or \
                        a_to_dev > b_to_dev or a_to_index > b_to_index:
                    tmp = topo_list[j]
                    topo_list[j] = topo_list[j + 1]
                    topo_list[j + 1] = tmp
        return topo_list

    @staticmethod
    def normalize_topo(*args):

        arg_list = Testbed._split_args(*args)
        [requests, properties, errs1] = Testbed.parse_topology(*arg_list)
        req_duts = dict()
        topo_dict = OrderedDict()
        for from_dev, to_dev, res, arg in requests:
            if not from_dev or not to_dev:
                continue
            if from_dev == "T":
                val = "{}{}{}{}:{}".format(to_dev, res.group(2), from_dev, res.group(1), res.group(3))
                topo_dict[val] = [to_dev, res.group(2), from_dev, res.group(1), res.group(3)]
                req_duts["{}{}".format(to_dev, res.group(2))] = 1
            else:
                req_duts["{}{}".format(from_dev, res.group(1))] = 1
                if to_dev == "D":
                    req_duts["{}{}".format(to_dev, res.group(2))] = 1
                if to_dev == "D" and int(res.group(1)) > int(res.group(2)):
                    val = "{}{}{}{}:{}".format(to_dev, res.group(2), from_dev, res.group(1), res.group(3))
                    topo_dict[val] = [to_dev, res.group(2), from_dev, res.group(1), res.group(3)]
                else:
                    topo_dict[arg] = [from_dev, res.group(1), to_dev, res.group(2), res.group(3)]
        topo_list_normalized = Testbed.sort_topo_dict(topo_dict)
        for dut in properties:
            for pname, pvalue in properties[dut].items():
                if dut:
                    topo_list_normalized.append("{}{}:{}".format(dut, pname, pvalue))
                else:
                    topo_list_normalized.append("{}:{}".format(pname, pvalue))
        [requests, properties, errs2] = Testbed.parse_topology(*topo_list_normalized)
        errs1.extend(errs2)
        return [requests, properties, req_duts.keys(), errs1]

    @staticmethod
    def preparse_topo(ignore, *args):
        topo_parts = []
        ignore_parts = [part.strip() for part in utils.make_list(ignore)]
        for topo in args:
            topo = topo.replace("'", "")
            topo = topo.replace('"', "")
            parts = [part.strip() for part in topo.split("=")]
            topo_parts.append("=".join(parts))
        requests, properties, _ = Testbed.parse_topology(*topo_parts)
        parts1, parts2 = [], []
        for req in requests:
            if req[3] and not req[3].endswith(":0"):
                parts1.append(req[3])
        parts1.sort()
        for remove in ignore_parts:
            for dut in properties.keys():
                properties.get(dut, {}).pop(remove, None)
        for dut, prop in properties.items():
            if dut is not None:
                continue
            for k, v in prop.items():
                if not v:
                    continue
                if v in ignore_parts:
                    continue
                parts2.append("{}={}".format(k, v))
        for dut, prop in properties.items():
            if dut is None:
                continue
            for k, v in prop.items():
                if not v:
                    continue
                if v in ignore_parts:
                    continue
                parts2.append("{}{}={}".format(dut, k, v))
        parts2.sort()
        parts1.extend(parts2)
        return " ".join(utils.find_duplicate(parts1)[1])

    @staticmethod
    def trace2(log, *args):
        # print(args)
        if log:
            log.info(args)

    @staticmethod
    def check_need_has(need, has):
        if has == "*":
            return True
        andcond = []
        for andneed in need.split("&"):
            orcond = []
            for orneed in andneed.split("|"):
                if orneed.startswith("!"):
                    if has is None or has.lower() != orneed[1:].lower():
                        orcond.append(True)
                elif has is not None and has.lower() == orneed.lower():
                    orcond.append(True)
            andcond.append(any(orcond))
        return all(andcond)

    @staticmethod
    def read_need(name, dut, props):
        for d in [dut, None]:
            if d in props and name in props[d]:
                return props[d][name]
        return None

    @staticmethod
    def trace_need_has(log, dut, dut_tb, props, name, phase, need, has=None):
        if not log:
            return
        if has is None:
            msg = "{}:{} DEV:{}/{} NEED:{} REQ:{}".format(phase, name, dut, dut_tb, need, props)
        else:
            msg = "{}:{} DEV:{}/{} NEED:{} HAS:{} REQ:{}".format(phase, name, dut, dut_tb, need, has, props)
        Testbed.trace2(log, msg)

    @staticmethod
    def check_model_suffix(log, tb, dut, dut_tb, props, prefix, cache):
        model_name = "MODEL{}".format(prefix)
        need = Testbed.read_need(model_name, dut, props)
        has = tb.get_device_param(dut_tb, model_name.lower(), None) if need else None

        Testbed.trace_need_has(log, dut, dut_tb, props, model_name, "CHK", need, None)

        # store cache and check if model need to match across devices
        cache.setdefault(model_name, {})
        for h, n in cache[model_name].values():
            if n == "__same__" and need == n and h != has:
                Testbed.trace2(log, "check_common_model{}".format(prefix), dut, dut_tb, props, need)
                return False
        cache[model_name][dut] = [has, need]

        if need and need != "__same__":
            if not Testbed.check_need_has(need, has):
                return False
        Testbed.trace_need_has(log, dut, dut_tb, props, model_name, "PASS", need, has)
        return True

    @staticmethod
    def check_model(log, tb, dut, dut_tb, props, cache):
        rv = Testbed.check_model_suffix(log, tb, dut, dut_tb, props, "", cache)
        for index in range(Testbed.max_dut_models):
            rv = rv and Testbed.check_model_suffix(log, tb, dut, dut_tb, props, index, cache)
        return rv

    @staticmethod
    def check_chip(log, tb, dut, dut_tb, props):
        has, need_chip = None, Testbed.read_need("CHIP", dut, props)
        need_chip_rev = Testbed.read_need("CHIP_REV", dut, props)
        Testbed.trace2(log, "check_chip_0", dut, dut_tb, props, need_chip, need_chip_rev)
        if need_chip:
            has = tb.get_device_param(dut_tb, "chip", None)
            Testbed.trace2(log, "check_chip_1", dut, dut_tb, props, need_chip, has)
            if not Testbed.check_need_has(need_chip, has):
                return False
        if need_chip_rev:
            has = tb.get_device_param(dut_tb, "chip_rev", None)
            Testbed.trace2(log, "check_chip_2", dut, dut_tb, props, need_chip_rev, has)
            if not Testbed.check_need_has(need_chip_rev, has):
                return False
        return True

    @staticmethod
    def check_type(log, tb, dut, dut_tb, props):
        has, need = None, Testbed.read_need("TYPE", dut, props)
        has = tb.get_device_type(dut_tb)
        Testbed.trace2(log, "check_type", dut, dut_tb, props, need, has)
        if need is not None:
            return Testbed.check_need_has(need, has)
        return bool(has in ["sonic", "sonicvs", "vsonic"])

    @staticmethod
    def check_tgen_model(log, tb, tg, props):
        has, need = None, Testbed.read_need("TGEN", None, props)
        Testbed.trace2(log, "check_tgen_model", tg, props, need)
        if need and need != "__all__":
            iginfo = tb.get_tg_info(tg)
            has = iginfo.type
            Testbed.trace2(log, "check_tgen_model", tg, props, need, has)
            return Testbed.check_need_has(need, has)
        return True

    @staticmethod
    def check_tgen_card(log, tb, tg, props):
        has, need = None, Testbed.read_need("TGCARD", None, props)
        Testbed.trace2(log, "check_tgen_card", tg, props, need)
        if need:
            iginfo = tb.get_tg_info(tg)
            has = getattr(iginfo, "card", "")
            Testbed.trace2(log, "check_tgen_card", tg, props, need, has)
            return Testbed.check_need_has(need, has)
        return True

    @staticmethod
    def check_tgen_speed(log, tb, tg, props):
        has, need = None, Testbed.read_need("TGSPEED", None, props)
        Testbed.trace2(log, "check_tgen_speed", tg, props, need)
        if need:
            iginfo = tb.get_tg_info(tg)
            has = getattr(iginfo, "speed", "")
            Testbed.trace2(log, "check_tgen_speed", tg, props, need, has)
            return Testbed.check_need_has(need, has)
        return True

    @staticmethod
    def check_dut_name_any(log, dut_list, props, req_duts):
        need_names = {}
        for dut in props:
            if "NAME" in props[dut]:
                need_names[dut] = props[dut]["NAME"]

        # check if NAMES can be used
        use_names = [need_names.get(dut, None) for dut in req_duts]
        if None not in use_names:
            use_names = ",".join(use_names)
            return Testbed.check_dut_names_any(log, dut_list, props, use_names)

        for need in need_names.values():
            found = False
            cre = re.compile("^" + need + "$")
            for has in dut_list:
                if cre.match(has):
                    found = True
            if not found:
                return None
        return dut_list

    @staticmethod
    def check_dut_names_any(log, dut_list, props, names=None):
        need0 = names or Testbed.read_need("NAMES", None, props)
        if not need0:
            return dut_list
        if "|" in need0:
            speedup = env.getint("SPYTEST_TESTBED_SPEEDUP_NAMES_GROUP_MATCH", 1)
            if not speedup:
                return dut_list
        for need in need0.split("|"):
            dut_list_new, need_list = [], need.split(",")
            for dut in need_list:
                cre = re.compile("^" + dut + "$")
                for has in dut_list:
                    if cre.match(has):
                        if has not in dut_list_new:
                            dut_list_new.append(has)
            if dut_list_new:
                return dut_list_new
        return []

    @staticmethod
    def check_dut_name(log, tb, dut, dut_tb, props):
        has, need = None, Testbed.read_need("NAME", dut, props)
        Testbed.trace2(log, "check_dut_name", dut, dut_tb, props, need)
        if not need:
            return True
        has = dut_tb
        Testbed.trace2(log, "check_dut_name", dut, dut_tb, props, need, has)
        return re.compile("^(" + need.strip() + ")$").match(dut_tb)

    @staticmethod
    def check_dut_names(log, tb, perm_list, props):
        has, need = None, Testbed.read_need("NAMES", None, props)
        Testbed.trace2(log, "check_dut_names", perm_list, props, need)
        if not need:
            return True
        has = ",".join(perm_list)
        Testbed.trace2(log, "check_dut_names", perm_list, props, need, has)
        return re.compile("^(" + need.strip() + ")$").match(has)

    @staticmethod
    def get_dut_list(val):
        if isinstance(val, list):
            return val
        return list(val.keys())

    def update_profile(self, profile):
        old = self.current_topo_index
        profile = profile or "{}={}".format(self.name, self.defaut_topo_index)
        for entry in utils.make_list(profile):
            for part in utils.split_byall(entry):
                expr = r"^{}\s*[:=]\s*\d+$".format(self.name)
                if not re.compile(expr).match(part):
                    continue
                expr = r"^{}\s*[:=]\s*(\d+)$".format(self.name)
                res = re.search(expr, part)
                self.set_topo_index(int(res.group(1)))
                break
        return old

    @staticmethod
    def identify_topology(log, tb, rdict, num, *args, **kwargs):
        old = tb.update_profile(kwargs.get("profile", ""))
        retval = Testbed.identify_topology_randomise(log, tb, rdict, num, False, *args)
        tb.set_topo_index(old)
        return retval

    def get_links_cached(self, from_dev, to_dev, dev_type, cache):
        if from_dev not in cache:
            cache[from_dev] = {}
        if to_dev not in cache[from_dev]:
            cache[from_dev][to_dev] = {}
        if dev_type in cache[from_dev][to_dev]:
            return cache[from_dev][to_dev][dev_type]
        entries = self.get_links(from_dev, to_dev, dev_type)
        cache[from_dev][to_dev][dev_type] = entries
        return entries

    @staticmethod
    def identify_topology_randomise(log, tb, rdict, num, randomise, *args):

        # normalize the topo and get the DUTs needed in topo
        arg_list = Testbed._split_args(*args)
        [requests, properties, req_duts, errs] = Testbed.normalize_topo(*arg_list)

        # bailout if TG card/model is not satisfied
        errs = Testbed.ensure_tgen_model_and_card(log, tb, properties, errs)
        if errs:
            Testbed.trace2(log, "tgen requirements not met", errs, properties)
            return [None, None, None]

        # build available duts by excluding used ones from all
        used_list = []
        if rdict:
            for duts in rdict.values():
                used_list.extend(duts)
        dut_list = []
        for dut in tb.get_device_names("DUT"):
            if dut not in used_list:
                dut_list.append(dut)

        links_cache, found_setups = {}, []
        for setup in range(0, num):
            dut_list2 = []
            used_list = [j for i in found_setups for j in i]
            for dut in dut_list:
                if dut not in used_list or randomise:
                    dut_list2.append(dut)
            dut_list2 = Testbed.check_dut_name_any(log, dut_list2, properties, req_duts)
            if not dut_list2:
                # does not satisfy one or more DUT NAME
                continue
            dut_list2 = Testbed.check_dut_names_any(log, dut_list2, properties)
            if len(dut_list2) < len(req_duts):
                # required numbers of DUTs are not present matching NAMES
                continue
            if randomise or properties.get(None, {}).get("SEARCH", "1") != "0":
                timedout = Testbed.check_match(log, tb, dut_list2, found_setups, links_cache,
                                               properties, randomise, req_duts, requests)
            elif not Testbed.check_match_combination(log, tb, dut_list2, found_setups,
                                                     links_cache, properties, requests):
                # No need to randomize but the current DUT list does not satify other constraints
                timedout = Testbed.check_match(log, tb, dut_list2, found_setups, links_cache,
                                               properties, randomise, req_duts, requests)
            else:
                timedout = False
            if timedout:
                break

        if not found_setups:
            Testbed.trace2(log, "not found match", "req_duts", req_duts, properties)
            return [None, None, None]

        # have match - create mini testbed
        setup_list = []
        for setup in found_setups:
            dut_names = []
            for dut in setup:
                dut_names.append(dut)
            setup_list.append(dut_names)

        return [setup_list, properties, errs]

    @staticmethod
    def check_match(log, tb, dut_list2, found_setups, links_cache, properties, randomise, req_duts, requests):
        start_time = get_timenow()
        perm_iterator = permutations(dut_list2, len(req_duts))
        for perm in perm_iterator:
            perm_list = list(perm)
            if randomise and perm_list in found_setups:
                continue
            if Testbed.check_match_combination(log, tb, perm_list, found_setups, links_cache, properties, requests):
                return False
            if get_elapsed(start_time, False) > tb.max_match_time:
                Testbed.trace2(log, "no matching found in {} seconds".format(tb.max_match_time), requests)
                return True
        return False

    @staticmethod
    def get_uniq_prop_value(log, tb, prop, dev_list):
        prop_value_list = []
        for device in dev_list:
            pval = tb.get_device_param(device, prop, None)
            if pval:
                prop_value_list.append(pval)
        prop_value_list.sort()
        return "-".join(prop_value_list)

    @staticmethod
    def check_match_combination(log, tb, perm_list, found_setups, links_cache, properties, requests):
        perm_dict = {"D{}".format(i + 1): item for i, item in enumerate(perm_list)}
        Testbed.trace2(log, perm_list, perm_dict)

        # check if names is enforced
        if not Testbed.check_dut_names(log, tb, perm_list, properties):
            Testbed.trace2(log, "no matching dut names", requests)
            return False

        # check if the constraints are met
        found_match = Testbed.check_match_dev(log, tb, links_cache, perm_dict, perm_list, properties, requests)
        if not found_match:
            return False

        # check the uniq constraint
        uniq = properties.get(None, {}).get("UNIQ", {})
        if uniq:
            uniq_values = []
            for found_setup in found_setups:
                uniq_value = Testbed.get_uniq_prop_value(log, tb, uniq, found_setup)
                Testbed.trace2(log, "UNIQ-OLD {} {}".format(found_setup, uniq_value))
                uniq_values.append(uniq_value)
            uniq_value = Testbed.get_uniq_prop_value(log, tb, uniq, found_match)
            Testbed.trace2(log, "UNIQ-NEW {} {}".format(found_match, uniq_value))
            if uniq_value in uniq_values:
                Testbed.trace2(log, "ignore match as duplicate", found_match, properties)
                return False

        # take the matched setup
        Testbed.trace2(log, "found match", found_match, properties)
        found_setups.append(found_match)
        return True

    @staticmethod
    def check_match_dev(log, tb, links_cache, perm_dict, perm_list, properties, requests):
        found_match, model_cache = [], {}
        for from_dev, to_dev, res, arg in requests:
            count = int(res.group(3))
            if from_dev == 'D' and to_dev == 'T':
                dut1_req = "D{}".format(res.group(1))
                Testbed.trace2(log, "checking-tg", arg, perm_list, dut1_req)
                if dut1_req not in perm_dict:
                    Testbed.trace2(log, "no match tg dut position", arg, count, dut1_req)
                    found_match = []
                    break
                dut1 = perm_dict[dut1_req]
                # check if name is enforced
                if not Testbed.check_dut_name(log, tb, dut1_req, dut1, properties):
                    Testbed.trace2(log, "no matching dut name", arg, count, dut1_req)
                    found_match = []
                    break
                # check if model is enforced
                if not Testbed.check_model(log, tb, dut1_req, dut1, properties, model_cache):
                    Testbed.trace2(log, "no matching dut model", arg, count, dut1_req)
                    found_match = []
                    break
                # check if chip is enforced
                if not Testbed.check_chip(log, tb, dut1_req, dut1, properties):
                    Testbed.trace2(log, "no matching dut chip", arg, count, dut1_req, properties)
                    found_match = []
                    break
                # check if type is enforced
                if not Testbed.check_type(log, tb, dut1_req, dut1, properties):
                    Testbed.trace2(log, "no matching dut type", arg, count, dut1_req, properties)
                    found_match = []
                    break
                # check if tg links are suffient
                entries = tb.get_links_cached(dut1, None, "TG", links_cache)
                if len(entries) < count:
                    Testbed.trace2(log, "no match tg links", arg, len(entries), count, dut1_req, dut1)
                    found_match = []
                    break
                found_match = perm_list
            elif from_dev == 'D' and to_dev == 'D':
                dut1_req = "D{}".format(res.group(1))
                dut2_req = "D{}".format(res.group(2))
                Testbed.trace2(log, "checking-dut", arg, perm_list, dut1_req, dut2_req, "links_req", count)
                if dut1_req not in perm_dict:
                    Testbed.trace2(log, "no match dut links - 1", arg, count, perm_list, dut1_req, dut2_req)
                    found_match = []
                    break
                if dut2_req not in perm_dict:
                    Testbed.trace2(log, "no match dut links - 2", arg, count, perm_list, dut1_req, dut2_req)
                    found_match = []
                    break
                dut1 = perm_dict[dut1_req]
                if not Testbed.check_model(log, tb, dut1_req, dut1, properties, model_cache):
                    Testbed.trace2(log, "no matching dut-1 model", arg, count, dut1_req, dut1)
                    found_match = []
                    break
                if not Testbed.check_chip(log, tb, dut1_req, dut1, properties):
                    Testbed.trace2(log, "no matching dut-1 chip", arg, count, dut1_req, dut1)
                    found_match = []
                    break
                if not Testbed.check_type(log, tb, dut1_req, dut1, properties):
                    Testbed.trace2(log, "no matching dut-1 type", arg, count, dut1_req, dut1)
                    found_match = []
                    break
                dut2 = perm_dict[dut2_req]
                if not Testbed.check_model(log, tb, dut2_req, dut2, properties, model_cache):
                    Testbed.trace2(log, "no matching dut-2 model", arg, count, dut2_req, dut2)
                    found_match = []
                    break
                if not Testbed.check_chip(log, tb, dut2_req, dut2, properties):
                    Testbed.trace2(log, "no matching dut-2 chip", arg, count, dut2_req, dut2)
                    found_match = []
                    break
                if not Testbed.check_type(log, tb, dut2_req, dut2, properties):
                    Testbed.trace2(log, "no matching dut-2 type", arg, count, dut2_req, dut2)
                    found_match = []
                    break
                entries = tb.get_links_cached(dut1, dut2, "DUT", links_cache)
                if len(entries) < count:
                    Testbed.trace2(log, "no match dut links", arg, len(entries), count, perm_list, dut1, dut2)
                    found_match = []
                    break
                found_match = perm_list
            else:
                print("UNKNOWN", arg)
        return found_match

    def get_device_name(self, name):
        profile = self.get_profile()
        for dinfo in profile.topology.devices.values():
            if dinfo["__name0__"] == name:
                return dinfo["__name__"]
        return None

    def get_all_files(self):
        return self.oyaml.get_files()

    def get_config_profile(self, default=""):
        profile = self.get_profile()
        try:
            return profile.topology.properties.profile
        except Exception:
            return default

    def save_visjs(self, used=None):
        used = used or []
        node_ids = dict()
        result = SpyTestDict()
        result.nodes = []
        result.links = []
        nid = 0
        lid = 0
        color_index = 0
        dut_colors = []
        for ll in used:
            if color_index < len(self.colors.used):
                color = self.colors.used[color_index]
                color_index = color_index + 1
            elif self.colors.used:
                color = self.colors.used[0]
            else:
                color = "red"
            dut_colors.append([ll, color])
        for d in self.get_device_names():
            dinfo = self.get_device_info(d)
            nid = nid + 1
            node = SpyTestDict()
            node.id = nid
            node.label = dinfo.alias
            if self.colors.free:
                node.color = self.colors.free
            for ll, color in dut_colors:
                if used and d in ll:
                    node.color = color
            if "topo_props" in dinfo:
                if "x" in dinfo.topo_props:
                    node.x = dinfo.topo_props.x * 100
                if "y" in dinfo.topo_props:
                    node.y = dinfo.topo_props.y * 100
            result.nodes.append(node)
            node_ids[d] = nid
        for d in self.get_device_names():
            for local, partner, remote in self.get_links(d):
                if node_ids[d] > node_ids[partner]:
                    continue
                lid = lid + 1
                link = SpyTestDict()
                link.id = lid
                link["from"] = node_ids[d]
                link.to = node_ids[partner]
                link.labelFrom = local
                link.labelTo = remote
                # link.label = "{}/{} -- {}/{}".format(d, local, partner, remote)
                smooth = SpyTestDict()
                smooth["type"] = 'curvedCW'
                smooth.roundness = 0.2
                # link.smooth = smooth
                result.links.append(link)
        return json.dumps(result, indent=4)

    @staticmethod
    def _copy_link_params(src, dst):
        exclude = ["EndDevice", "EndPort", "incr"]
        exclude.extend(["from_port", "from_dut"])
        exclude.extend(["to_port", "to_dut"])
        exclude.extend(["from_type", "to_type"])
        exclude.extend(["__name1__", "__name2__"])
        exclude.extend(["__name3__", "__name4__"])
        exclude.extend(dst.keys())
        utils.copy_items(src, dst, exclude=exclude)

    def rebuild_topo_file0(self, devices, properties, expand_yaml=None,
                           use_aliases=None, fmt=2, shuffle_ports=False):
        remove_def_link_params, generate_intf_range = False, False
        # remove_def_link_params = bool(fmt == 3)
        profile = self.get_profile()
        used_devices = dict()
        new_topo = SpyTestDict()
        new_topo2 = SpyTestDict()
        properties = properties or {}
        selected_tgen = properties.get("selected-tgen", None)
        needed_tgen_type = properties.get(None, {}).get("TGEN", None)
        if not selected_tgen:
            # mark the first tgen as selected tgen
            for tg in self.get_device_names("TG"):
                selected_tgen = tg
                break

        # special case of include all tgens
        if needed_tgen_type == "__all__":
            needed_tgen_type = selected_tgen = None

        for dut in devices:
            dinfo = self.get_device_info(dut)
            new_topo[dinfo.alias] = SpyTestDict()
            new_topo[dinfo.alias].interfaces = SpyTestDict()
            used_devices[dut] = 1

            for linfo in profile.unconnected_links.values():
                if dut not in [linfo.from_dut]:
                    continue
                link_ent = SpyTestDict()
                self._copy_link_params(linfo, link_ent)
                new_topo[dinfo.alias].interfaces[linfo.from_port] = link_ent

            for local, partner, remote, name in self.get_links(dut, name=True):
                pdinfo = self.get_device_info(partner)
                link_ent = SpyTestDict()
                if pdinfo.type == "TG":
                    if needed_tgen_type and needed_tgen_type != pdinfo.properties.type:
                        link_ent.reserved = True
                    elif selected_tgen and selected_tgen != pdinfo.__name__:
                        link_ent.reserved = True
                    else:
                        link_ent.EndDevice = pdinfo.alias
                        link_ent.EndPort = remote
                        used_devices[partner] = 1
                        if partner not in new_topo and partner not in new_topo2:
                            new_topo2[partner] = SpyTestDict()
                            if "topo_props" in pdinfo:
                                new_topo2[partner].properties = pdinfo.topo_props
                elif partner in devices:
                    link_ent.EndDevice = pdinfo.alias
                    link_ent.EndPort = remote
                    used_devices[partner] = 1
                else:
                    link_ent.reserved = True
                self._copy_link_params(profile.links[name], link_ent)
                rev = new_topo.get(pdinfo.alias, {}).get("interfaces", {}).get(remote, None)
                if not rev:
                    new_topo[dinfo.alias].interfaces[local] = link_ent
                if "topo_props" in dinfo:
                    new_topo[dinfo.alias].properties = dinfo.topo_props
                    tmp_intf = new_topo[dinfo.alias].pop("interfaces")
                    new_topo[dinfo.alias].interfaces = tmp_intf
        for d, dinfo in new_topo2.items():
            new_topo[d] = new_topo2[d]
        for d in list(new_topo.keys()):
            if "interfaces" in new_topo[d] and not new_topo[d].interfaces:
                del new_topo[d].interfaces
            if not new_topo[d]:
                del new_topo[d]
        for d, dinfo in new_topo.items():
            dinfo.breakout = SpyTestDict()
            for port, option in profile.breakout[d].items():
                dinfo.breakout[port] = option
        d1 = copy.deepcopy(self.oyaml_data)
        d2 = copy.deepcopy(self.oyaml_data_copy)
        if env.get("SPYTEST_TESTBED_RENAME_DEVICES"):
            d2.devices = self.devices
        else:
            d2.devices = d1.devices
        dev_nodes = SpyTestDict()
        for d, dinfo in d2.devices.items():
            # override the breakout
            for port, option in profile.breakout[d].items():
                dinfo.setdefault("breakout", SpyTestDict())
                dinfo.breakout[port] = option
            if "__name__" in dinfo and dinfo.__name__ in used_devices:
                dev_nodes[d] = dinfo
            if fmt in [3]:
                try:
                    del dinfo.breakout
                except Exception:
                    pass
        d2.devices = dev_nodes
        d2.topology = new_topo

        ##########################################
        # remove topologies and breakout sections
        ##########################################
        try:
            del d2.topologies
        except Exception:
            pass
        for i in range(10):
            try:
                del d2["topology{}".format(i)]
            except Exception:
                pass
        for dinfo in d2.topology.values():
            if fmt in [2]:
                try:
                    del dinfo.breakout
                except Exception:
                    pass
        ##########################################
        ##########################################
        # recreate topologies section
        ##########################################
        # d3 = copy.deepcopy(self.oyaml_data_copy)
        # d2.topologies = d3.topologies

        # shuffle interfaces
        for d in list(d2.topology.keys()):
            if not shuffle_ports:
                continue
            if "interfaces" not in d2.topology[d]:
                continue
            if not d2.topology[d].interfaces:
                continue
            intf_list = list(d2.topology[d].interfaces)
            seed = utils.get_random_seed()
            Random(seed).shuffle(intf_list)
            new_interfaces = SpyTestDict()
            for intf in intf_list:
                new_interfaces[intf] = d2.topology[d].interfaces[intf]
            d2.topology[d].interfaces = new_interfaces

        # rebuild current and restore config sections
        current_configs, restore_configs = {}, {}

        # save current config files
        for d, dinfo in d2.devices.items():
            if not self.expand_yaml or dinfo["type"] != "DUT":
                continue
            dut = dinfo.__name__
            current_configs[dut] = self.get_config(dut, "current")
            restore_configs[dut] = self.get_config(dut, "restore")
            try:
                if None in properties and "CONFIG" in properties[None]:
                    current_configs[dut] = self.read_config_file(properties[None]["CONFIG"])
                elif dut in properties and "CONFIG" in properties[dut]:
                    current_configs[dut] = self.read_config_file(properties[dut]["CONFIG"])
            except Exception as e:
                msg = "exception: {}".format(str(e))
                self.logger.error(msg)

        # change config profile and replace global config files
        for d, dinfo in d2.devices.items():
            if not self.expand_yaml or dinfo["type"] != "DUT":
                continue
            dut = dinfo.__name__
            dinfo.properties.config = "config-{}".format(dinfo.alias)
            obj = SpyTestDict()
            obj.current = current_configs[dut]
            obj.restore = restore_configs[dut]
            d2.configs[dinfo.properties.config] = obj

        # remove temp data
        for d, dinfo in d2.devices.items():
            del dev_nodes[d].type
            del dev_nodes[d].__name__
            del dev_nodes[d].__name0__
            del dev_nodes[d].alias
            try:
                del dev_nodes[d].topo_props
            except Exception:
                pass

        if fmt == 3:
            new_topo = SpyTestDict()
            for d, dinfo in d2.topology.items():
                new_topo[d] = SpyTestDict()
                new_topo[d].properties = dinfo.pop("properties", None)
                if not new_topo[d].properties:
                    del new_topo[d].properties
                new_topo[d].breakout = dinfo.pop("breakout", None)
                if not new_topo[d].breakout:
                    del new_topo[d].breakout
                for key, value in dinfo.items():
                    new_topo[d][key] = value
                if remove_def_link_params and "interfaces" in new_topo[d]:
                    for intf in new_topo[d].interfaces.values():
                        params = intf.pop("params", None)
                        if params and params not in ["def_link", "def_tg_link"]:
                            intf.params = params
            for d, dinfo in new_topo.items():
                if not generate_intf_range:
                    continue
                if "interfaces" not in dinfo:
                    continue
                if "breakout" not in dinfo:
                    continue
                breakout_intf = dinfo.breakout.keys()
                for intf, value in dinfo.interfaces.items():
                    if intf not in breakout_intf:
                        continue
                    EndDevice = value.get("EndDevice", None)
                    EndPort = value.get("EndPort", None)
                    if not EndPort or not EndDevice:
                        continue
                    if not EndPort.startswith("Ethernet"):
                        continue
                    local_breakoput = dinfo.breakout.get(intf, None)
                    remote_breakout = new_topo[EndDevice].get("breakout", {}).get(EndPort, None)
                    # print(intf, value, local_breakoput)
                    if local_breakoput != remote_breakout:
                        continue
            # d2.topology = new_topo
            del d2.topology
            d2.topologies = SpyTestDict({0: new_topo})

        if expand_yaml is None:
            expand_yaml = self.expand_yaml
        if use_aliases is None:
            use_aliases = self.use_aliases
        if fmt == 3:
            return self.oyaml.dump(d2, expand_yaml, use_aliases, width=1000)
        return self.oyaml.dump(d2, expand_yaml, use_aliases)

    def rebuild_topo_file(self, devices, properties,
                          expand_yaml=None, use_aliases=None, fmt=2, **kwargs):
        old = self.update_profile(kwargs.get("profile", ""))
        retval = self.rebuild_topo_file0(devices, properties, expand_yaml, use_aliases, fmt)
        self.set_topo_index(old)
        return retval

    def validate_testbed(self, tb_list=None):
        tg_ips = []
        rps_ips = []
        consoles = []
        self.validation_errors = []
        for tb in tb_list or []:
            tg_ips.extend(tb._validate_tgen_info())
            rps_ips.extend(tb._validate_rps_info([]))
            consoles.extend(tb._validate_consoles([], [], []))

        # validate the current testbed against collected info
        tg_ips.extend(self._validate_tgen_info())
        rps_ips.extend(self._validate_rps_info(tg_ips))
        consoles.extend(self._validate_consoles(tg_ips, rps_ips, consoles))
        return self.validation_errors

    @staticmethod
    def write_file(yaml, prefix="testbed_", suffix=".yaml", filename=None):
        fp = tempfile.NamedTemporaryFile(delete=False, prefix=prefix, suffix=suffix, mode='w')
        fp.write(yaml)
        if not filename:
            return fp.name
        try:
            fp2 = tempfile.mkdtemp(prefix=prefix, suffix=suffix)
            new_filename = os.path.join(fp2, filename)
            shutil.move(fp.name, new_filename)
            return new_filename
        except Exception:
            return fp.name

    @staticmethod
    def read_config_file(filename):
        try:
            oyaml = OrderedYaml(filename, [testbeds_root])
            obj = oyaml.get_data()
            assert (isinstance(obj.current, list))
            return obj.current
        except Exception:
            return None

import os
import sys
import re
import copy
import json
import shutil
import logging
import tempfile
import yaml
from itertools import permutations
from collections import OrderedDict

from spytest.ordyaml import OrderedYaml
from spytest.dicts import SpyTestDict
import utilities.common as utils

testbeds_root = os.path.join(os.path.dirname(__file__), '..')
testbeds_root = os.path.join(os.path.abspath(testbeds_root), "testbeds")

class Testbed(object):
    """
    todo: Update Documentation
    """

    def __init__(self, filename=None, logger=None, cfg=None, flex_dut=False):
        """
        Construction of Testbed object
        :param filename:
        :type filename:
        :param logger:
        :type logger:
        """
        self._paths = []
        self._paths.append(os.getenv("SPYTEST_USER_ROOT"))
        self._paths.append(testbeds_root)
        self.validation_errors = []
        self.oyaml = None
        self.offset = None
        self.common_tgen_ports = True
        self.cfg = cfg
        if cfg:
            self.flex_dut = cfg.flex_dut
            self.filemode = cfg.filemode
            self.exclude_devices = cfg.exclude_devices
            self.include_devices = cfg.include_devices
        else:
            self.flex_dut = flex_dut
            self.filemode = False
            self.exclude_devices = None
            self.include_devices = None
        if self.exclude_devices:
            self.exclude_devices = utils.split_byall(self.exclude_devices, True)
        if self.include_devices:
            self.include_devices = utils.split_byall(self.include_devices, True)
        self.derived = SpyTestDict()
        self.derived.devices = None
        self.topology = SpyTestDict()
        self.devices = SpyTestDict()
        self.colors = SpyTestDict()
        self.services = SpyTestDict()
        self.configs = SpyTestDict()
        self.builds = SpyTestDict()
        self.errors = SpyTestDict()
        self.speeds = SpyTestDict()
        self.instrument = SpyTestDict()
        self.build_default_errors()
        self.links = SpyTestDict()
        self.reserved_links = SpyTestDict()
        self.params = SpyTestDict()
        self.global_params = SpyTestDict()
        self.devices_state = SpyTestDict()
        self.devices_port_state = SpyTestDict()
        self.pertest_topo_checking = False
        self.valid = False
        self.logger = logger or logging.getLogger()
        self._load_and_check(filename)

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
        """
        todo: Update Documentation
        :return:
        :rtype:
        """
        return self.valid

    def get_file_path(self):
        return self.oyaml.get_file_path()

    def get_raw(self, expanded=False):
        return self.oyaml.get_raw(expanded)

    def get_dut_access(self, dut_id):
        retval = SpyTestDict()
        for dinfo in self.topology.devices.values():
            if dinfo["__name__"] == dut_id:
                retval["dut_name"] = dinfo.__name0__
                retval["alias"] = dinfo.alias
                retval["ip"] = dinfo.access.ip
                retval["port"] = dinfo.access.port
                retval["mgmt_ipmask"] = dinfo.access.get("mgmt_ipmask" , None)
                retval["mgmt_gw"] = dinfo.access.get("mgmt_gw" , None)
                retval["username"] = dinfo.credentials.username
                retval["password"] = dinfo.credentials.password
                retval["altpassword"] = dinfo.credentials.altpassword
                retval["errors"] = self.get_error(dut_id, None)
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
                else:
                    device_model = "sonic"
                if dinfo.access.protocol == "ssh":
                    retval["access_model"] = "{}_ssh".format(device_model)
                elif dinfo.access.protocol == "sshcon":
                    retval["sshcon_username"] = dinfo.access.username
                    retval["sshcon_password"] = dinfo.access.password
                    retval["access_model"] = "{}_sshcon".format(device_model)
                else:
                    retval["access_model"] = "{}_terminal".format(device_model)
                retval["device_model"] = device_model
                return retval
        return None

    def get_device_info(self, name, dtype=None):
        for dut, dinfo in self.topology.devices.items():
            if not dtype or dinfo.type == dtype:
                if dinfo["__name__"] == name:
                    return dinfo
        return None

    def get_device_alias(self, name, only=False):
        for dut, dinfo in self.topology.devices.items():
            if dinfo.__name__ == name or dinfo.__name0__ == name:
                if only:
                    return dinfo.alias
                return "{}({})".format(dinfo.__name0__, dinfo.alias)
        return "UNKNOWN"

    def _load_and_check(self, filename):
        # testbed file order: argument, env, default
        if not filename:
            filename = os.getenv("SPYTEST_TESTBED_FILE", "testbed.yaml")
        if self._load_yaml(filename):
            self.valid = True
            if self._build_link_info():
                self._validate()
        return self.topology

    def _valition_error(self, msg):
        self.logger.error(msg)
        self.validation_errors.append(msg)

    def _validate(self):
        self.validation_errors = []
        self._validate_passwords()
        self._validate_config_files()
        tg_ips = self._validate_tgen_info()
        rps_ips = self._validate_rps_info(tg_ips)
        self._validate_consoles(tg_ips, rps_ips, [])
        self._validate_links()

    # verify duplicate access details
    def _validate_consoles(self, tg_ips, rps_ips, exclude):
        consoles = []
        for dev, dinfo in self.topology.devices.items():
            if dinfo.type != "DUT":
                continue
            access = dinfo.access
            if access.ip in tg_ips:
                msg = "{}: IP {} already used for TG".format(dev, access.ip)
                self._valition_error(msg)
                self.valid = False
            if access.ip in rps_ips:
                msg = "{}: IP {} already used for RPS".format(dev, access.ip)
                self._valition_error(msg)
                self.valid = False
            ent = "{}:{}:{}".format(access.protocol, access.ip, access.port)
            if ent in exclude:
                msg = "{}: already used".format(ent)
                self._valition_error(msg)
                self.valid = False
            if ent not in consoles:
                consoles.append(ent)
                continue
            msg = "Duplicate console info {}".format(ent)
            self._valition_error(msg)
            self.valid = True
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
                self._valition_error(msg)
                self.valid = False
            if tinfo.ip not in types:
                types[tinfo.ip] = tinfo.type
            elif types[tinfo.ip] != tinfo.type:
                msg = "same ip ({}) cant be used for multiple TG types"
                msg = msg.format(tinfo.ip)
                self._valition_error(msg)
                self.valid = False
        for dev in self.get_device_names("TG"):
            tinfo = self.get_tg_info(dev)
            if "ix_server" in tinfo:
                for ix_server in utils.make_list(tinfo.ix_server):
                    if ix_server in ix_servers:
                        continue
                    ix_servers.append(ix_server)
                    if ix_server in types and tinfo.ip != ix_server:
                        msg = "ix_server ip ({}) already used as TG IP"
                        msg = msg.format(ix_server)
                        self._valition_error(msg)
                        self.valid = False
        ix_servers.extend(types.keys())
        return ix_servers

    # verify duplicate RPS IP addresses
    def _validate_rps_info(self, tg_ips):
        outlets = dict()
        models = dict()
        for dev in self.get_device_names("DUT"):
            tinfo = self.get_rps(dev)
            if tinfo == None:
                continue
            if tinfo.ip not in models:
                models[tinfo.ip] = tinfo.model
            elif models[tinfo.ip] != tinfo.model:
                msg = "same ip ({}) cant be used for multiple RPS models"
                msg = msg.format(tinfo.ip)
                self._valition_error(msg)
                self.valid = False
        for dev in self.get_device_names("DUT"):
            tinfo = self.get_rps(dev)
            if tinfo == None or tinfo.model == "vsonic":
                continue
            if tinfo.ip not in outlets:
                outlets[tinfo.ip] = []
            if tinfo.outlet in outlets[tinfo.ip]:
                msg = "RPS outlet ({}/{}) is already used"
                msg = msg.format(tinfo.ip, tinfo.outlet)
                self._valition_error(msg)
                self.valid = False
            else:
                outlets[tinfo.ip].append(tinfo.outlet)
        for ip in outlets:
            if ip in tg_ips:
                msg = "RPS IP {} already used for TG".format(ip)
                self._valition_error(msg)
                self.valid = False
        return outlets.keys()

    def _validate_links(self):
        pairs = dict()
        for dev in self.get_device_names():
            for local, partner, remote in self.get_links(dev):
                alias = self.get_device_alias(dev)
                pair = "{}/{}".format(alias, local)
                palias = self.get_device_alias(partner)
                to = "{}/{}".format(palias, remote)
                if pair in pairs:
                    msg = "Duplicate Links {} {} connecting to {}"
                    msg = msg.format(pairs[pair], to, pair)
                    self.logger.error(msg)
                    self.valid = False
                else:
                    pairs[pair] = to

    # verify same passwords
    def _validate_passwords(self):
        for dev, dinfo in self.devices.items():
            if dinfo.type != "DUT" or self.get_device_type(dev) != "sonic":
                continue
            if dinfo.credentials.password in dinfo.credentials.altpassword or \
                dinfo.credentials.altpassword in dinfo.credentials.password:
                msg = "password and altpasswords are alike for device {}".format(dev)
                self.logger.error(msg)
                self.valid = False

    # verify presence of config files if specified
    def _validate_config_files(self):
        for dut in self.get_device_names("DUT"):
            # verify services
            if not self.get_service(dut, None):
                msg = "invalid services for {}".format(dut)
                self.logger.error(msg)
                self.valid = False
            # verify builds
            if not self.get_build(dut, None):
                msg = "invalid build for {}".format(dut)
                self.logger.error(msg)
                self.valid = False
            # verify configs section
            if not self.get_config(dut, None):
                msg = "invalid config for {}".format(dut)
                self.logger.error(msg)
                self.valid = False
                continue
            # verify config files
            for scope in ["current", "restore"]:
                files = self.get_config(dut, scope)
                if files is None:
                    if scope in ["current", "restore"]:
                        self.valid = False
                    continue
                for filename in files:
                    file_path = self.get_config_file_path(filename)
                    if file_path:
                        continue
                    msg = "{} config file {} not found".format(scope, filename)
                    self.logger.error(msg)
                    if not self.filemode:
                        self.valid = False

    def _is_ignored_device(self, dut):
        if dut in self.devices:
            if "reserved" not in self.devices[dut]:
                return False
        return True

    def _build_link_info(self):
        #utils.print_data(self.topology, "self.topology-1")

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

        connected_links = []
        reserved_links = []
        # add devices if missing in topology but present in connections
        add_devices = []
        unreserved_devices = SpyTestDict()

        # removed reserved/ignored devices from topology
        for dut, dinfo in self.topology.devices.items():
            if not self._is_ignored_device(dut):
                unreserved_devices[dut] = dinfo
        self.topology.devices = unreserved_devices

        for dut, dinfo in self.topology.devices.items():
            #utils.print_data(dinfo, "dinfo - {}".format(dut))
            if not dinfo or "interfaces" not in dinfo:
                continue
            if not isinstance(dinfo.interfaces, dict):
                msg = "interfaces section of {} is invalid - ignoring".format(dut)
                self.logger.warning(msg)
                #self.valid = False
                del dinfo.interfaces
                continue
            for link, linfo in dinfo.interfaces.items():
                if "reserved" in linfo:
                    msg = "Reserved link: {}/{}".format(dut, link)
                    self.logger.debug(msg)
                    reserved_links.append([dut, link, linfo])
                    continue
                if "EndDevice" not in linfo:
                    msg = "EndDevice is not specified for interface {}/{}".format(dut, link)
                    self.logger.error(msg)
                    self.valid = False
                    continue
                if "EndPort" not in linfo:
                    msg = "EndPort is not specified for interface {}/{}".format(dut, link)
                    self.logger.error(msg)
                    self.valid = False
                    continue
                EndDevice = linfo.EndDevice
                if EndDevice not in self.devices:
                    msg = "EndDevice {} is not found".format(EndDevice)
                    self.logger.error(msg)
                    self.valid = False
                    continue
                if self._is_ignored_device(EndDevice):
                    msg = "EndDevice {} is reserved ignoring {}/{}".format(EndDevice, dut, link)
                    self.logger.debug(msg)
                    reserved_links.append([dut, link, linfo])
                    continue
                connected_links.append([dut, link, linfo])
                if EndDevice not in self.topology.devices:
                    add_devices.append(EndDevice)
            del self.topology.devices[dut]["interfaces"]
        for dut, dinfo in self.topology.devices.items():
            if dut not in self.devices:
                msg = "Device {} is not present in devices section".format(dut)
                self.logger.error(msg)
                self.valid = False
                return False
            else:
                if dinfo:
                    props = dinfo.get("properties", None)
                else:
                    props = dict()
                self.topology.devices[dut] = self.devices[dut]
                self.topology.devices[dut]["topo_props"] = props
        for dut in add_devices:
            self.topology.devices[dut] = self.devices[dut]
        #utils.print_data(self.topology, "self.topology-2")

        # add DUT internal name
        dut_index = tg_index = 1
        for dut, dinfo in self.topology.devices.items():
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
        #utils.print_yaml(self.topology, "self.topology-4")

        for dut, link, linfo in reserved_links:
            ent = SpyTestDict({
                "from_port": link, "from_dut": self.devices[dut].__name__
            })
            link_name = "{}-{}".format(ent.from_dut, ent.from_port)
            self.reserved_links[link_name] = ent
        #utils.print_yaml(self.reserved_links, "self.reserved_links")

        self.links = SpyTestDict()
        for dut, link, linfo in connected_links:
            ent = SpyTestDict({
                "from_port": link, "from_dut": self.devices[dut].__name__,
                "to_port": linfo.EndPort, "to_dut": self.devices[linfo.EndDevice].__name__,
                "from_type": self.devices[dut].type,
                "to_type": self.devices[linfo.EndDevice].type,
                "speed": linfo.get("speed")
            })
            ent.params = None if "params" not in linfo else linfo.params
            link_name = "{}-{}-{}-{}".format(ent.from_dut, ent.from_port,
                                             ent.to_dut, ent.to_port)

            # if what is added is duplicate
            ent = SpyTestDict({
                "to_port": link, "to_dut": self.devices[dut].__name__,
                "from_port": linfo.EndPort, "from_dut": self.devices[linfo.EndDevice].__name__,
                "to_type": self.devices[dut].type,
                "from_type": self.devices[linfo.EndDevice].type,
                "speed": linfo.get("speed")
            })
            link_name2 = "{}-{}-{}-{}".format(ent.from_dut, ent.from_port,
                                             ent.to_dut, ent.to_port)
            if link_name2 not in self.links:
                self.links[link_name] = ent
            else:
                msg = "Ignoring duplicate link {} existing {}".format(link_name, link_name2)
                self.logger.debug(msg)

        # add link name variables
        link_indexes = SpyTestDict()
        for link_name, linfo in self.links.items():
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

    def _load_yaml(self, filename):
        errs = []
        try:
            user_root = os.getenv("SPYTEST_USER_ROOT")
            if user_root:
                self.oyaml = OrderedYaml(filename, [user_root, testbeds_root])
            else:
                self.oyaml = OrderedYaml(filename, [testbeds_root])
            if not self.oyaml.is_valid():
                errs = self.oyaml.get_errors()
                self.logger.error(errs)
                return None
            obj = self.oyaml.get_data()
            #utils.print_yaml(obj, "TESTBED FILE CONTENT")
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
            if "topology" not in obj:
                errs.append("topology not found")
            if errs:
                raise ValueError("Invalid testbed file: " + filename, errs)
            if "global" in obj and "params" in obj["global"]:
                self.global_params = obj["global"]["params"]
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
                self.logger.debug("instrument section not found")
            else:
                self.instrument = obj["instrument"]
            self.params = obj["params"]
            self.topology = obj["topology"]
            self.colors = SpyTestDict()
            try:
                self.colors.free = obj["colors"]["free"]
                self.colors.used = obj["colors"]["used"]
                assert(isinstance(self.colors.used, list))
                assert(isinstance(self.colors.free, str))
            except Exception as e:
                #self.logger.warning("using default colors for topology diagram {}".format(e))
                self.colors.free = None
                self.colors.used = ["red"]
            if "devices" not in self.topology:
                devices = SpyTestDict()
                for k,v in self.topology.items():
                    devices[k] = v
                self.topology.clear()
                self.topology.properties = SpyTestDict()
                self.topology.properties.verifier = "NA"
                self.topology.devices = devices

            # override device properties from command line
            if self.cfg and self.cfg.dev_prop:
                for k,v in self.cfg.dev_prop:
                    for dev, dinfo in self.devices.items():
                        if dinfo.properties:
                            dinfo.properties[k] = v

            # override ixnetwork from command line
            if self.cfg and self.cfg.ixserver:
                ix_server = ",".join(self.cfg.ixserver)
                for dev, dinfo in self.devices.items():
                    if dinfo.device_type == "TGEN" and dinfo.properties:
                        dinfo.properties["ix_server"] = ix_server

            return self.topology
        except ValueError as e:
            msg = "\r\nInvalid testbed file {}.\n{}\n".format(filename, errs)
            self.logger.error(msg)
        except Exception as e:
            #import pdb, traceback, sys
            #extype, value, tb = sys.exc_info()
            #traceback.print_exc()
            #pdb.post_mortem(tb)
            self.topology = None
            self.devices = None
            self.services = None
            self.configs = None
            self.builds = None
            self.errors = None
            self.speeds = None
            self.instrument = None
            self.params = None
            msg = "\r\nInvalid testbed file {}.\n{}\n".format(filename, e)
            self.logger.error(msg)
        return None

    def _get_dut_property(self, dut, prop, table, subprop, defprop=None):
        for d, dinfo in self.topology.devices.items():
            if dinfo["__name__"] == dut:
                if "properties" not in dinfo:
                    msg = "properties not availbale for {}".format(d)
                    self.logger.info(msg)
                    return None
                if prop not in dinfo.properties:
                    if not defprop:
                        print("'{}' not set in properties for {}".format(prop, d))
                        return None
                    msg = "'{}' not set in properties for {} assuming '{}'".format(prop, d, defprop)
                    if prop != "instrument":
                        self.logger.debug(msg)
                    ref = defprop
                else:
                    ref = dinfo.properties[prop]
                table_object = getattr(self, table)
                if not table_object or ref not in table_object:
                    msg = "{}/{} is not found".format(table, ref)
                    self.logger.debug(msg)
                    return None
                if not subprop or not table_object[ref]:
                    return table_object[ref]
                if subprop not in table_object[ref]:
                    msg = "{} is not specified in {}/{}".format(subprop, table, ref)
                    self.logger.info(msg)
                    return None
                return table_object[ref][subprop]
        return None

    def get_device_type(self, dut, default="sonic"):
        dinfo = self.get_device_info(dut)
        if not dinfo:
            return default
        if dinfo.device_type in ["DevSonic"]:
            return "sonic"
        return dinfo.device_type

    def get_service(self, dut, name):
        """
        todo: Update Documentation
        :param name:
        :type name:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        return self._get_dut_property(dut, "services", "services", name)

    def get_config(self, dut, scope):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param scope:
        :type scope:
        :return:
        :rtype:
        """
        return self._get_dut_property(dut, "config", "configs", scope)

    def get_config_file_path(self, file_name):
        return self._locate(file_name)

    def get_build(self, dut, scope):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param scope:
        :type scope:
        :return:
        :rtype:
        """
        return self._get_dut_property(dut, "build", "builds", scope)

    def get_error(self, dut, scope):
        return self._get_dut_property(dut, "errors", "errors", scope, "default")

    def get_speed(self, dut, scope=None):
        rv = self._get_dut_property(dut, "speed", "speeds", scope, None)
        if not rv: rv = SpyTestDict()
        for local, partner, remote in self.get_links(dut):
            value = self.get_link_param(dut, local, "speed", None)
            if value: rv[local] = value
        return rv

    def get_instrument(self, dut, scope=None):
        return self._get_dut_property(dut, "instrument", "instrument", scope, "default")

    def get_param(self, name, default):
        """
        todo: Update Documentation
        :param name:
        :type name:
        :param default:
        :type default:
        :return:
        :rtype:
        """
        if not self.global_params:
            return default
        if not name:
            return self.global_params
        if name not in self.global_params:
            return default
        return self.global_params[name]

    def get_device_param(self, dut, name, default):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param name:
        :type name:
        :param default:
        :type default:
        :return:
        :rtype:
        """
        for d, dinfo in self.topology.devices.items():
            if dinfo["__name__"] == dut:
                if "properties" not in dinfo:
                    print("properties not availbale for {}".format(d))
                    return default
                if "params" not in dinfo.properties:
                    print("params not set in properties for {}".format(d))
                    return default

                # check for per dut params overriden
                if "params" in dinfo and name in dinfo.params:
                    return dinfo.params[name]

                ref = dinfo.properties.params
                if ref not in self.params:
                    print("params {} not found".format(ref))
                    return default
                if not name:
                    return self.params[ref]
                if name not in self.params[ref]:
                    return default
                return self.params[ref][name]
        return default

    def get_link_param(self, dut, local, name, default):
        for link, linfo in self.links.items():
            if linfo["from_dut"] == dut and linfo["from_port"] == local:
                pass
            elif linfo["to_dut"] == dut and linfo["to_port"] == local:
                pass
            else:
                continue

            # see if there is paramater overriden
            if name in linfo:
                return linfo[name]

            if "params" not in linfo or linfo.params is None:
                print("params not set in properties for {}".format(link))
                return default
            ref = linfo.params
            if ref not in self.params:
                print("params {} not found".format(ref))
                return default
            if not name:
                return self.params[ref]
            if name not in self.params[ref]:
                return default
            return self.params[ref][name]
        return default

    def get_breakout(self, dut):
        retval = []
        dinfo = self.get_device_info(dut)
        if dinfo:
            breakout = dinfo.get("breakout")
            if breakout:
                for port, option in breakout.items():
                    retval.append([port, option])
        return retval

    def get_device_names(self, dtype=None):
        """
        Returns names of all devices of given type
        :return: device names of given type
        :rtype: list
        """
        if self.flex_dut:
            if dtype == "DUT" and self.derived.devices:
                return self.derived.devices
        retval = []
        for dut, dinfo in self.topology.devices.items():
            if not dtype or dinfo["type"] == dtype:
                name = dinfo["__name__"]
                if name not in retval:
                    retval.append(name)
        return retval

    def get_rerved_links(self, dut):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        retval = []
        for link, linfo in self.reserved_links.items():
            if linfo["from_dut"] == dut:
                retval.append(linfo["from_port"])
        return retval

    def get_links(self, dut, peer=None, dtype=None):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        retval = []
        for link, linfo in self.links.items():
            if peer:
                if linfo["from_dut"] == dut and linfo["to_dut"] == peer:
                    if not dtype or dtype == linfo["to_type"]:
                        retval.append([linfo["from_port"], linfo["to_dut"],
                                       linfo["to_port"]])
                if linfo["to_dut"] == dut and linfo["from_dut"] == peer:
                    if not dtype or dtype == linfo["from_type"]:
                        retval.append([linfo["to_port"], linfo["from_dut"],
                                       linfo["from_port"]])
            else:
                if linfo["from_dut"] == dut:
                    if not dtype or dtype == linfo["to_type"]:
                        retval.append([linfo["from_port"], linfo["to_dut"],
                                       linfo["to_port"]])
                if linfo["to_dut"] == dut:
                    if not dtype or dtype == linfo["from_type"]:
                        retval.append([linfo["to_port"], linfo["from_dut"],
                                       linfo["from_port"]])
        return retval

    def get_tg_info(self, tg):
        """
        Get the properties of given TGEN device
        :param tg: Name of the TGEN device
        :type tg: string
        :return: properties dictionary
        :rtype: dict
        """
        for ent, dinfo in self.topology.devices.items():
            if dinfo.type == "TG":
                if not tg or dinfo["__name__"] == tg:
                    rv = SpyTestDict()
                    rv.name = dinfo.__name__
                    rv.ip = dinfo.properties.ip
                    rv.type = dinfo.properties.type
                    rv.version = dinfo.properties.version
                    rv.card = getattr(dinfo.properties, "card", "")
                    if "ix_server" in dinfo.properties:
                        rv.ix_server = dinfo.properties.ix_server
                    if "ix_port" in dinfo.properties:
                        rv.ix_port = dinfo.properties.ix_port
                    return rv
        return None

    def get_rps(self, dut):
        """
        Returns RPS details read from testbed file for given DUT
        :param dut: DUT identifier
        :type dut: basestring
        :return: RPS parameters dictionary
        :rtype: dict
        """
        rv = self.get_device_info(dut)
        if rv and "rps" in rv:
            return rv["rps"]
        return None

    def get_testbed_vars(self):
        """
        returns the testbed variables in a dictionary
        :return: testbed variables dictionary
        :rtype: dict
        """
        rv = SpyTestDict()
        rv.tgen_list = self.get_device_names("TG")
        rv.tgen_ports = SpyTestDict()
        rv.dut_list = self.get_device_names("DUT")
        dut_index = 1
        for dut in rv.dut_list:
            dut_name = "D{}".format(dut_index)
            rv[dut_name] = dut
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
            for to_index in range(from_index+1, dut_index):
                from_name = "D{}".format(from_index)
                to_name = "D{}".format(to_index)
                (from_dev, to_dev) = (rv[from_name], rv[to_name])
                links = self.get_links(from_dev, to_dev)
                lnum = 1
                for local, partner, remote in links:
                    lname1 = "{}{}P{}".format(from_name, to_name, lnum)
                    lname2 = "{}{}P{}".format(to_name, from_name, lnum)
                    lnum = lnum + 1
                    rv[lname1] = local
                    rv[lname2] = remote
        if self.common_tgen_ports:
            for to_index in range(1, dut_index):
                lnum = 1
                for from_index in range(1, tg_index):
                    from_name = "T{}".format(from_index)
                    to_name = "D{}".format(to_index)
                    (from_dev, to_dev) = (rv[from_name], rv[to_name])
                    links = self.get_links(from_dev, to_dev)
                    for local, partner, remote in links:
                        lname1 = "T1{}P{}".format(to_name, lnum)
                        lname2 = "{}T1P{}".format(to_name, lnum)
                        lnum = lnum + 1
                        rv[lname1] = local
                        rv[lname2] = remote
                        rv.tgen_ports[lname1] = [from_name, tg_types[from_name], local]
        else:
            for from_index in range(1, tg_index):
                for to_index in range(1, dut_index):
                    from_name = "T{}".format(from_index)
                    to_name = "D{}".format(to_index)
                    (from_dev, to_dev) = (rv[from_name], rv[to_name])
                    links = self.get_links(from_dev, to_dev)
                    lnum = 1
                    for local, partner, remote in links:
                        lname1 = "{}{}P{}".format(from_name, to_name, lnum)
                        lname2 = "{}{}P{}".format(to_name, from_name, lnum)
                        lnum = lnum + 1
                        rv[lname1] = local
                        rv[lname2] = remote
                        rv.tgen_ports[lname1] = [from_name, tg_types[from_name], local]

        return rv

    def get_access(self, string=True):
        retval = []
        for dut, dinfo in self.topology.devices.items():
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

    def get_topo(self):
        retval = []
        exclude = []
        for dut, dinfo in self.topology.devices.items():
            partners = OrderedDict()
            for local, partner, remote in self.get_links(dut):
                partners[partner] = partners.setdefault(partner, 0) + 1
            for partner in partners:
                if "{}--{}".format(dut, partner) in exclude:
                    continue
                exclude.append("{}--{}".format(partner, dut))
                pdinfo = self.get_device_info(partner)
                retval.append("{}{}:{}".format(dinfo.__name0__,pdinfo.__name0__, partners[partner]))
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

        if self.pertest_topo_checking and int(res.group(3)) > 0:
            if from_type == 'D' and not self.devices_state[from_dev]:
                errs.append("dut_down")
                return [False, from_dev, to_dev]
            if to_type == 'D' and not self.devices_state[to_dev]:
                errs.append("dut_down")
                return [False, from_dev, to_dev]
            for local, partner, remote in links:
                if not self.devices_port_state["{}:{}".format(from_dev, local)]:
                    errs.append("link_down")
                    return [False, from_dev, to_dev]
        return [True, from_dev, to_dev]

    @staticmethod
    def _split_args(*args):
        sep=os.getenv("SPYTEST_TOPO_SEP", None)
        arg_list = []
        for arg in args:
            arg_list.extend(utils.split_byall(arg, sep=sep))
        return arg_list

    @staticmethod
    def parse_topology (*args):
        requests=[]
        properties=dict()
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
            elif re.compile(r"^D\d+CHIP[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)CHIP[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["CHIP"] = res.group(2)
            elif re.compile(r"^D\d+NAME[:=]\S+$").match(arg):
                res = re.search(r"^D(\d+)NAME[:=](\S+)$", arg)
                properties.setdefault("D{}".format(res.group(1)), dict())["NAME"] = res.group(2)
            elif re.compile(r"^BUILD[:=]\S+$").match(arg):
                res = re.search(r"^BUILD[:=](\S+)$", arg)
                properties.setdefault(None, dict())["BUILD"] = res.group(1)
            elif re.compile(r"^CONFIG[:=]\S+$").match(arg):
                res = re.search(r"^CONFIG[:=](\S+)$", arg)
                properties.setdefault(None, dict())["CONFIG"] = res.group(1)
            elif re.compile(r"^MODEL[:=]\S+$").match(arg):
                res = re.search(r"^MODEL[:=](\S+)$", arg)
                properties.setdefault(None, dict())["MODEL"] = res.group(1)
            elif re.compile(r"^CHIP[:=]\S+$").match(arg):
                res = re.search(r"^CHIP[:=](\S+)$", arg)
                properties.setdefault(None, dict())["CHIP"] = res.group(1)
            elif re.compile(r"^TGEN[:=]\S+$").match(arg):
                res = re.search(r"^TGEN[:=](\S+)$", arg)
                properties.setdefault(None, dict())["TGEN"] = res.group(1)
            elif re.compile(r"^NAME[:=]\S+$").match(arg):
                res = re.search(r"^NAME[:=](\S+)$", arg)
                properties.setdefault(None, dict())["NAME"] = res.group(1)
            elif re.compile(r"^NAMES[:=]\S+$").match(arg):
                res = re.search(r"^NAMES[:=](\S+)$", arg)
                properties.setdefault(None, dict())["NAMES"] = res.group(1)
            elif re.compile(r"^CONSOLE_ONLY$").match(arg):
                properties.setdefault(None, dict())["CONSOLE_ONLY"] = True
            elif re.compile(r"^TGCARD[:=]\S+$").match(arg):
                res = re.search(r"^TGCARD[:=](\S+)$", arg)
                properties.setdefault(None, dict())["TGCARD"] = res.group(1)
            else:
                errs.append("{}: unsupported".format(arg))
                requests.append([None, None, 0, arg])
        if errs:
            print("parse_topology--errors", errs)
        return [requests, properties, errs]

    @staticmethod
    def ensure_tgen_model_and_card(logger, tb, properties, errs=[]):

        # check tg model requirements
        for tg in tb.get_device_names("TG"):
            if not Testbed.check_tgen_model(logger, tb, tg, properties):
                errs.append("no_tgen_model")

        # check tg card requirements
        for tg in tb.get_device_names("TG"):
            if not Testbed.check_tgen_card(logger, tb, tg, properties):
                errs.append("no_tgen_card")

        return errs

    def ensure_min_topology(self, *args):
        [requests, properties, errs] = self.parse_topology(*args)
        if errs: return [errs, properties]

        logger = None #self.logger

        # bailout if TG card/model is not satified
        Testbed.ensure_tgen_model_and_card(logger, self, properties, errs)
        if errs: return [errs, properties]

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
        for dut in topo_dinfo:
            if not Testbed.check_model(logger, self, dut, dut, properties):
                errs.append("no_dut_model")

        # check chip requirements
        for dut in topo_dinfo:
            if not Testbed.check_chip(logger, self, dut, dut, properties):
                errs.append("no_dut_chip")

        # bail out on errors if not flex dut
        if not errs or not self.flex_dut:
            return [errs, properties]

        [setup_list, properties, errs2] = self.identify_topology(logger, self, None, 1, *args)
        if not setup_list:
            return [errs, properties]
        self.derived.devices = setup_list[0]
        return [[], properties]

    def reset_derived_devices(self):
        self.derived.devices = None

    @staticmethod
    def sort_topo_dict(topo_dict):
        topo_list = list(topo_dict.keys())
        l = len(topo_list)
        for i in range(0, l):
            for j in range(0, l-i-1):
                [a_from_dev, a_from_index, a_to_dev, a_to_index, a_count] = topo_dict.get(topo_list[j])
                [b_from_dev, b_from_index, b_to_dev, b_to_index, b_count] = topo_dict.get(topo_list[j+1])
                if a_from_dev > b_from_dev or a_from_index > b_from_index or \
                   a_to_dev > b_to_dev or a_to_index > b_to_index:
                    tmp = topo_list[j]
                    topo_list[j]= topo_list[j + 1]
                    topo_list[j + 1]= tmp
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
                val = "{}{}{}{}:{}".format(to_dev, res.group(2), \
                           from_dev, res.group(1), res.group(3))
                topo_dict[val] = [to_dev, res.group(2), from_dev, res.group(1), res.group(3)]
                req_duts["{}{}".format(to_dev, res.group(2))] = 1
            else:
                req_duts["{}{}".format(from_dev, res.group(1))] = 1
                if to_dev == "D":
                    req_duts["{}{}".format(to_dev, res.group(2))] = 1
                if to_dev == "D" and int(res.group(1)) > int(res.group(2)):
                    val = "{}{}{}{}:{}".format(to_dev, res.group(2), \
                              from_dev, res.group(1), res.group(3))
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
    def trace2(log, *args):
        #print(args)
        if log:
            log.info(args)

    @staticmethod
    def check_need_has(need, has):
        if has is None:
            return False
        if has == "*":
            return True
        for n in need.split("|"):
            if n.startswith("!"):
                if has.lower() != n[1:].lower():
                    return True
            elif has.lower() == n.lower():
                return True
        return False

    @staticmethod
    def check_model(log, tb, dut, dut_tb, props):
        need = None
        if None in props:
            if "MODEL" in props[None]:
                need = props[None]["MODEL"]

        if dut in props:
            if "MODEL" in props[dut]:
                need = props[dut]["MODEL"]

        Testbed.trace2(log, "check_model_0", dut, dut_tb, props, need)
        if need:
            has = tb.get_device_param(dut_tb, "model", None)
            Testbed.trace2(log, "check_model_1", dut, dut_tb, props, need, has)
            if has is None:
                return False
            if not re.compile(need, re.IGNORECASE).match(has):
                return False
        return True

    @staticmethod
    def check_chip(log, tb, dut, dut_tb, props):
        need = None
        if None in props:
            if "CHIP" in props[None]:
                need = props[None]["CHIP"]

        if dut in props:
            if "CHIP" in props[dut]:
                need = props[dut]["CHIP"]

        Testbed.trace2(log, "check_chip_0", dut, dut_tb, props, need)
        if need:
            has = tb.get_device_param(dut_tb, "chip", None)
            Testbed.trace2(log, "check_chip_1", dut, dut_tb, props, need, has)
            return Testbed.check_need_has(need, has)
        return True

    @staticmethod
    def check_tgen_model(log, tb, tg, props):
        need = None
        if None in props:
            if "TGEN" in props[None]:
                need = props[None]["TGEN"]

        Testbed.trace2(log, "check_tgen_model", tg, props, need)
        if need:
            iginfo = tb.get_tg_info(tg)
            has = iginfo.type
            Testbed.trace2(log, "check_tgen_model", tg, props, need, has)
            return Testbed.check_need_has(need, has)
        return True

    @staticmethod
    def check_tgen_card(log, tb, tg, props):
        need = None
        if None in props:
            if "TGCARD" in props[None]:
                need = props[None]["TGCARD"]

        Testbed.trace2(log, "check_tgen_card", tg, props, need)
        if need:
            iginfo = tb.get_tg_info(tg)
            has = getattr(iginfo, "card", "")
            Testbed.trace2(log, "check_tgen_card", tg, props, need, has)
            return Testbed.check_need_has(need, has)
        return True

    @staticmethod
    def check_dut_name_any(log, dut_list, props):
        need_list = []
        for dut in props:
            if "NAME" in props[dut]:
                need_list.append(props[dut]["NAME"])

        for need in need_list:
            found = False
            for has in dut_list:
                if re.compile(need).match(has):
                    found = True
            if not found:
                return False
        return True

    @staticmethod
    def check_dut_names_any(log, dut_list, props):
        need = None
        if None in props:
            if "NAMES" in props[None]:
                need = props[None]["NAMES"]

        if need and "|" not in need:
            dut_list_new = []
            for dut in need.split(","):
                for has in dut_list:
                    if re.compile(dut).match(has):
                        if has not in dut_list_new:
                            dut_list_new.append(has)
            return dut_list_new
        return dut_list

    @staticmethod
    def check_dut_name(log, tb, dut, dut_tb, props):
        need = None
        if None in props:
            if "NAME" in props[None]:
                need = props[None]["NAME"]

        if dut in props:
            if "NAME" in props[dut]:
                need = props[dut]["NAME"]

        Testbed.trace2(log, "check_dut_name", dut, dut_tb, props, need)
        if need:
            has = dut_tb
            Testbed.trace2(log, "check_dut_name", dut, dut_tb, props, need, has)
            if not re.compile(need).match(dut_tb):
                return False
        return True

    @staticmethod
    def check_dut_names(log, tb, perm_list, props):
        need = None
        if None in props:
            if "NAMES" in props[None]:
                need = props[None]["NAMES"]

        Testbed.trace2(log, "check_dut_names", perm_list, props, need)
        if need:
            has = ",".join(perm_list)
            Testbed.trace2(log, "check_dut_names", perm_list, props, need, has)
            if not re.compile(need).match(has):
                return False
        return True

    @staticmethod
    def get_dut_list(val):
        if isinstance(val, list):
            return val
        return list(val.keys())

    @staticmethod
    def identify_topology(log, tb, rdict, num, *args):

        # normalize the topo and get the DUTs needed in topo
        arg_list = Testbed._split_args(*args)
        [requests, properties, req_duts, errs] = Testbed.normalize_topo(*arg_list)

        # bailout if TG card/model is not satified
        Testbed.ensure_tgen_model_and_card(log, tb, properties, errs)
        if errs:
            Testbed.trace2(log, "tgen requirements not met", errs, properties)
            return [None, None, None]

        # build available duts by excluding used ones from all
        used_list = []
        if rdict:
            for reqid, duts in rdict.items():
                used_list.extend(duts)
        dut_list = []
        for dut in tb.get_device_names("DUT"):
            if dut not in used_list:
                dut_list.append(dut)
        #print(dut_list)

        found_setups = []
        for setup in range(0, num):
          dut_list2 = []
          used_list = [j for i in found_setups for j in i]
          for dut in dut_list:
              if dut not in used_list:
                  dut_list2.append(dut)
          if not Testbed.check_dut_name_any(log, dut_list2, properties):
            continue
          dut_list2 = Testbed.check_dut_names_any(log, dut_list2, properties)
          if len(dut_list2) < len(req_duts):
            continue
          found_match = []
          perm_iterator = permutations(dut_list2, len(req_duts))
          for perm in perm_iterator:
            perm_list = list(perm)
            perm_dict = {"D{}".format(i+1) : item for i, item in enumerate(perm_list)}
            Testbed.trace2(log, perm, perm_list, perm_dict)
            # check if names is enforced
            if not Testbed.check_dut_names(log, tb, perm_list, properties):
                Testbed.trace2(log, "no matching dut names", requests)
                found_match = []
                continue
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
                    if not Testbed.check_model(log, tb, dut1_req, dut1, properties):
                        Testbed.trace2(log, "no matching dut model", arg, count, dut1_req)
                        found_match = []
                        break
                    # check if chip is enforced
                    if not Testbed.check_chip(log, tb, dut1_req, dut1, properties):
                        Testbed.trace2(log, "no matching dut chip", arg, count, dut1_req, properties)
                        found_match = []
                        break
                    # check if tg links are suffient
                    entries = tb.get_links(dut1, None, "TG")
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
                    if not Testbed.check_model(log, tb, dut1_req, dut1, properties):
                        Testbed.trace2(log, "no matching dut-1 model", arg, count, dut1_req, dut1)
                        found_match = []
                        break
                    if not Testbed.check_chip(log, tb, dut1_req, dut1, properties):
                        Testbed.trace2(log, "no matching dut-1 chip", arg, count, dut1_req, dut1)
                        found_match = []
                        break
                    dut2 = perm_dict[dut2_req]
                    if not Testbed.check_model(log, tb, dut2_req, dut2, properties):
                        Testbed.trace2(log, "no matching dut-2 model", arg, count, dut2_req, dut2)
                        found_match = []
                        break
                    if not Testbed.check_chip(log, tb, dut2_req, dut2, properties):
                        Testbed.trace2(log, "no matching dut-2 chip", arg, count, dut2_req, dut2)
                        found_match = []
                        break
                    entries = tb.get_links(dut1, dut2, "DUT")
                    if len(entries) < count:
                        Testbed.trace2(log, "no match dut links", arg, len(entries), count, perm_list, dut1, dut2)
                        found_match = []
                        break
                    found_match = perm_list
                else:
                    print("UNKNOWN", arg)
            if found_match:
              Testbed.trace2(log, "found match", found_match, "req_duts", req_duts, properties)
              found_setups.append(found_match)
              break

        #import pdb;pdb.set_trace()
        if not found_setups:
            Testbed.trace2(log, "not found match", "req_duts", req_duts, properties)
            return [None, None, None]

        # have match - create mini testbed
        setup_list = []
        for setup in found_setups:
            #new_rdict = OrderedDict()
            dut_names = []
            for dut in setup:
                #dinfo = tb.get_device_info(dut)
                #new_rdict[dut] = dinfo.alias
                dut_names.append(dut)
            #setup_list.append(new_rdict)
            setup_list.append(dut_names)

        return [setup_list, properties, errs]

    def get_device_name(self, name):
        for dut, dinfo in self.topology.devices.items():
            if dinfo["__name0__"] == name:
                return dinfo["__name__"]
        return None

    def get_all_files(self):
        return self.oyaml.get_files()

    def get_verifier(self, default="NA"):
        try:
            return self.topology.properties.verifier
        except:
            return default

    def get_config_profile(self, default="NA"):
        try:
            return self.topology.properties.profile
        except:
            return default

    def save_visjs(self, used=[]):
        node_ids = dict()
        result = SpyTestDict()
        result.nodes = []
        result.links = []
        nid = 0
        lid = 0
        color_index = 0
        dut_colors = []
        for l in used:
            if color_index < len(self.colors.used):
                color = self.colors.used[color_index]
                color_index = color_index + 1
            elif self.colors.used:
                color = self.colors.used[0]
            else:
                color = "red"
            dut_colors.append([l, color])
        for d in self.get_device_names():
            dinfo = self.get_device_info(d)
            nid = nid + 1
            node = SpyTestDict()
            node.id = nid
            node.label = dinfo.alias
            if self.colors.free:
                node.color = self.colors.free
            for l, color in dut_colors:
                if used and d in l:
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
                #link.label = "{}/{} -- {}/{}".format(d, local, partner, remote)
                smooth = SpyTestDict()
                smooth["type"] = 'curvedCW'
                smooth.roundness = 0.2
                #link.smooth = smooth
                result.links.append(link)
        return json.dumps(result, indent=4)

    def rebuild_topo_file(self, devices, properties):
        used_devices = dict()
        topology = SpyTestDict()
        for dut in devices:
            dinfo = self.get_device_info(dut)
            topology[dinfo.alias] = SpyTestDict()
            topology[dinfo.alias].interfaces = SpyTestDict()
            used_devices[dut] = 1
            for local, partner, remote in self.get_links(dut):
                pdinfo = self.get_device_info(partner)
                link_ent = SpyTestDict()
                if pdinfo.type == "TG":
                    if None in properties and "TGEN" in properties[None] and \
                       properties[None]["TGEN"] != pdinfo.properties.type:
                        link_ent.reserved = True
                    else:
                        link_ent.EndDevice = pdinfo.alias
                        link_ent.EndPort = remote
                        used_devices[partner] = 1
                elif partner in devices:
                        link_ent.EndDevice = pdinfo.alias
                        link_ent.EndPort = remote
                        used_devices[partner] = 1
                else:
                    link_ent.reserved = True
                topology[dinfo.alias].interfaces[local] = link_ent
        d2 = copy.deepcopy(self.oyaml.obj)
        dev_nodes = SpyTestDict()
        for d, dinfo in d2.devices.items():
            if "__name__" in dinfo and dinfo.__name__ in used_devices:
                dev_nodes[d] = dinfo
        d2.devices = dev_nodes
        d2.topology.devices = topology

        current_configs = dict()
        restore_configs = dict()

        # save current config files
        for d, dinfo in d2.devices.items():
            if dinfo["type"] != "DUT":
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
                print("exception", str(e))

        # change config profile and replace global config files
        for d, dinfo in d2.devices.items():
            if dinfo["type"] != "DUT":
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

        return yaml.dump(d2, default_flow_style=False)

    def validate_testbed(self, tb_list=[]):
        tg_ips = []
        rps_ips = []
        consoles = []
        self.validation_errors = []
        for tb in tb_list:
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
        except:
            return fp.name

    @staticmethod
    def read_config_file(filename):
        try:
            oyaml = OrderedYaml(filename, [testbeds_root])
            obj = oyaml.get_data()
            assert(isinstance(obj.current, list))
            return obj.current
        except:
            return None

    def _unit_tests(self):
        for d in self.get_device_names("DUT"):
            print("DUT--NAME: " + d)
        utils.print_yaml(self.links, "LINKS")
        print("get_service(D1,ftp): ", self.get_service("D101", "ftp"))
        print("get_service(D1,tftp): ", self.get_service("D101", "tftp"))
        print("get_service(D1,None): ", self.get_service("D101", None))
        print("get_rps(D1): ", self.get_rps("D101"))
        print("get_links(D1): ", self.get_links("D101"))
        print("get_links(D2): ", self.get_links("D102"))
        print("get_links(D3): ", self.get_links("D103"))
        print("get_links(D1,D2): ", self.get_links("D101", "D102"))
        print("get_links(D1,D3): ", self.get_links("D101", "D103"))
        print("get_links(D2,D3): ", self.get_links("D102", "D103"))
        print("get_links(D3,D2): ", self.get_links("D103", "D102"))
        print("get_testbed_vars(): ", self.get_testbed_vars())


if __name__ == "__main__":
    logging.basicConfig()
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    def_filename = "../testbeds/sample_sonic_terminal_1d.yaml"
    file_name = sys.argv[1] if len(sys.argv) >= 2 else def_filename
    t = Testbed(file_name)
    t.flex_dut = True
    print(t.get_speed("D1", None))
    #print(t.identify_topology(None, t, None, 1, "D1T1:1", "CHIP=td2|th2"))
    #print(t.identify_topology(None, t, None, 1, "D1T1:1", "CHIP=!td3"))
    #print(t.identify_topology(None, t, None, 1, "D1T1:1", "CHIP=td3"))
    #print(t.identify_topology(None, t, None, 1, "D1T1:1", "TGCARD=t1|t2"))
    #print(t.identify_topology(None, t, None, 1, "D1"))
    print(t.ensure_min_topology("D1D2:1 D2D3:1 D3D4:1 TGEN=stc|ixia"))
    print(t.ensure_min_topology("D1D2:1 D2D3:1 D3D4:1 TGEN=stc"))
    print(t.ensure_min_topology("D1D2:1 D2D3:1 D3D4:1 TGEN=ixia"))
    sys.exit(0)
    o = t.topology
    with open('expanded-v2.yml', 'w') as outfile:
        yaml.dump(o, outfile, default_flow_style=False)
    topo = o
    for dd, d_info in topo.devices.items():
        utils.print_data(d_info, "{}".format(dd))
    utils.print_yaml(topo, "topology")
    print(t.ensure_min_topology("D1T1:20"))
    print(t.ensure_min_topology("D1D2:20"))
    print(t.get_all_files())
    print(t.get_device_alias("D101"))
    print(t.parse_topology("D1T1:1", "D1D2:1"))
    print(t.parse_topology("D1T1:1", "D1CONFIG:test.yaml", "D1MODEL:AS7712", "CONFIG:abc.yaml", "MODEL:AS7712"))
    print(t.get_device_param("D101", "model", "unknown"))
    print(t.get_build("D101", None))
    print(t.get_error("D101", None))
    print(t.get_breakout("D101"))
    with open('all.json', 'w') as outfile:
        outfile.write(t.save_visjs())
    t._unit_tests()
    print(t.get_device_names())
    for dd in t.get_device_names("DUT"):
        print(dd, t.get_device_alias(dd), t.get_rerved_links(dd))
    print("VALID", t.valid, t._validate())
    print(t.get_speed("D101", None))
    print(t.get_speed("D101", "Ethernet43"))
    print(t.get_device_param("D101", "show_delay", "1"))
    print(t.get_device_param("D101", "hostname", "unknown"))
    print(t.ensure_min_topology("D1D2:3", "D2D3:3"))
    print(t.ensure_min_topology("D1D2:3", "D1D3:3"))
    #print(t.ensure_min_topology("D1T1:1", "TGEN:ixia2"))
    #print(t.identify_topology(None, t, None, 1, "D1T1:1", "TGEN:ixia"))
    ##print(t.identify_topology(None, t, None, 1, "D1D2:6 D2D3:4 D2D4:4 D4:D5:6 D5D6:4"))
    tbvars = t.get_testbed_vars()
    print("get_testbed_vars(): ", tbvars)
    for dd in t.get_device_names("DUT"):
        print("DUT--NAME: " + dd)
        print("get_links({}): ", dd, t.get_links(dd))
    for dd in t.get_device_names("TG"):
        print("DUT--NAME: " + dd)
        print("get_links({}): ", dd, t.get_links(dd))
    print("========================================")
    print(t.normalize_topo("D1D24", "D1NAME:DUT-8", "D2NAME:DUT-4"))
    print("========================================")
    #print(t.get_raw())
    print(t.identify_topology(None, t, None, 2, "D1 D2 D3 D4", "NAMES:DUT-1,DUT-2,DUT-7,DUT-8|DUT-5,DUT-6,DUT-3,DUT-4"))
    print(t.identify_topology(None, t, None, 2, "D1T1:4 D1D2:6 D2D3:3 D1D3:3 D2T1:2 D3T1:2"))
    print("========================================")
    t.flex_dut = True
    print(t.identify_topology(None, t, None, 2, "D1T1:1", "D2T1:2", "D1D2:2", "D1MODEL:Accton-AS7326-56X", "D2MODEL:Accton-AS7326-56X"))
    print(t.ensure_min_topology("D1T1:1", "D2T1:2", "D1D2:2", "D1MODEL:Accton-AS7326-56X", "D2MODEL:Accton-AS7326-56X2" ))
    print(t.identify_topology(log, t, None, 2, "D1 D2 D3 D4 NAMES:DUT-1,DUT-2,DUT-7,DUT-8|DUT-5,DUT-6,DUT-3,DUT-4"))
    print(t.get_access())
    print(t.ensure_min_topology("D1", "CONSOLE_ONLY"))
    print(t.get_topo())
    print(t.ensure_min_topology("D1", "CHIP=TD3|TD2"))
    breakout_options = t.get_device_param("SS4-2", "breakout", None)


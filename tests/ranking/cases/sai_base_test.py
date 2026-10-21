# Copyright 2021-present Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# The below software in this distribution may have been modified
# by Clounix ("Clounix Modifications"). All Clounix Modifications
# are copyright © Clounix(Shanghai) Technology Limited.
#
# The below software in this distribution may have been modified
# by Centec . All Centec Modifications
# are copyright © Centec(Suzhou) Technology Limited.
#
"""
This file contains base classes for PTF test cases as well as a set of
additional useful functions.

Tests will usually inherit from one of the base classes to have the controller
and/or dataplane automatically set up.
"""
import os
import sys
import time
import inspect
from threading import Thread

from collections import OrderedDict
from unittest import SkipTest

from ptf import packet
from ptf import config
from ptf import testutils
import codecs
from ptf.base_tests import BaseTest

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from sai_thrift import sai_rpc
import LogConfig
from data_module.port import Port

import sai_thrift.sai_adapter as adapter
from ranking_test import sai_capture
from ranking_test.runtime_control import RuntimeControl, run_local

_CASE_ROOT = os.path.dirname(os.path.abspath(__file__))
_ATTR_MAP_PATHS = (
    os.path.join(_CASE_ROOT, 'ranking_test', 'attr_map.json'),
    os.path.join(os.path.dirname(_CASE_ROOT), 'resources', 'attr_map.json'),
)
for _ATTR_MAP_PATH in _ATTR_MAP_PATHS:
    if os.path.isfile(_ATTR_MAP_PATH):
        break
else:
    raise RuntimeError('attr_map.json is required for ranking capture')
_entries = sai_capture.load_map(_ATTR_MAP_PATH)
_wrapped = sai_capture.install(adapter)
print('sai_capture: %d map entries, %d adapter functions wrapped' %
      (_entries, _wrapped), file=sys.stderr)

# Import adapter symbols only after installing capture so flat case imports bind
# the runtime wrappers rather than unwrapped generated functions.
from sai_utils import *

from config.port_configer import PortConfiger
from config.config_db_loader import ConfigDBLoader
from config.port_config_ini_loader import PortConfigInILoader
from ranking_test.sai_test_result import TestResultCollector, SpecRegistry, Measurement

# Perf cases carry no capability evidence, so the attr capture is pure cost
# there. ext_sai_srv6_test is deliberately absent: it is a capability case
# that happens to share the ext_ prefix.
PERF_MODULES = frozenset((
    'ext_sai_counter_stress_test',
    'ext_sai_l2_scale_test',
    'ext_sai_l3_ecmp_scale_test',
    'ext_sai_l3_neighbor_scale_test',
    'ext_sai_l3_nexthop_scale_test',
    'ext_sai_l3_route_scale_test',
    'ext_sai_l3_scale_base',
))

ROUTER_MAC = '00:77:66:55:44:00'
THRIFT_PORT = 9092


def _rpc_port(test_params):
    value = test_params.get('rpc_port', THRIFT_PORT)
    if isinstance(value, bool):
        raise ValueError('rpc_port must be an integer from 1 through 65535')
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError('rpc_port must be an integer from 1 through 65535') from error
    if port < 1 or port > 65535 or str(port) != str(value):
        raise ValueError('rpc_port must be an integer from 1 through 65535')
    return port


SKIP_TEST_NO_RESOURCES_MSG = 'Not enough resources to run test'
PLATFORM = os.environ.get('PLATFORM')
platform_map = {'broadcom': 'brcm', 'barefoot': 'bfn', 'cisco': 'cisco',
                'mellanox': 'mlnx', 'common': 'common', 'marvell': 'mrvl',
                'centec':'ctc','clounix': 'clx'}
import re


def get_thrift_version():
    result = run_local(['dpkg', '-l'])
    thrift_lines = [line for line in result.stdout.split('\n') if 'thrift' in line]
    version_pattern = re.compile(r'libthrift-dev\s+([\d.]+)')
    for line in thrift_lines:
        match = version_pattern.search(line)
        if match:
            return match.group(1)
    return None


def get_local_interface_ipv4(interface):
    result = run_local(['ifconfig', interface])
    for line in result.stdout.splitlines():
        fields = line.split()
        if 'inet' in fields:
            index = fields.index('inet')
            if index + 1 < len(fields):
                value = fields[index + 1]
                return value[5:] if value.startswith('addr:') else value
    return ''


def get_platform():
    """
    Get the platform token.

    If environment variable [PLATFORM] doesn't exist, then the default platform will be 'common'.
    If environment variable [PLATFORM] exist but platform name is unknown raise ValueError.
    If environment variable [PLATFORM] exist but platform name is unspecified,
    then the default platform will be 'common'.
    If specified any one, it will try to concert it from standard name to a shortened name (case insensitive). \r
    \ti.e. Broadcom -> brcm
    """
    pl = 'common'

    if 'PLATFORM' in os.environ:
        pl_low = PLATFORM.lower()
        if pl_low in platform_map.keys():
            pl = platform_map[pl_low]
        elif pl_low in platform_map.values():
            pl = pl_low
        elif PLATFORM == '':
            print("Platform not set. The common platform was selected")
        else:
            raise ValueError("Undefined platform: {}.".format(pl_low))
    else:
        print("Platform not set. The common platform was selected")

    return pl

if get_platform() == 'cisco':
    from sai_thrift.ttypes import sai_thrift_route_entry_t as sai_thrift_route_entry_t_origin
    from sai_thrift.ttypes import sai_thrift_neighbor_entry_t as sai_thrift_neighbor_entry_t_origin


def _saiserver_host_pid(control, container_parameter='host_control_container'):
    result = control.run_remote([
        'docker', 'top', control.container(container_parameter), '-eo', 'pid,args'])
    for line in result.stdout.splitlines()[1:]:
        fields = line.split(None, 1)
        if len(fields) == 2 and '/usr/sbin/saiserver' in fields[1]:
            return fields[0]
    raise RuntimeError('saiserver process was not found after start')


def start_saiserver(control, container_parameter='host_control_container'):
    control.run_remote([
        'docker', 'exec', '-d', control.container(container_parameter),
        '/usr/sbin/saiserver', '-p', '/etc/sai.d/sai.profile',
        '-f', '/usr/share/sonic/hwsku/port_config.ini'])
    time.sleep(2)
    return _saiserver_host_pid(control, container_parameter)


def kill_saiserver(control, container_parameter='host_control_container'):
    control.run_container(['killall5'], container_parameter)


RUN_REG = 0

class ThriftInterface(BaseTest):
    """
    Get and format a port map, retrieve test params, and create an RPC client

    Have the following class attributes:
        port_map_loaded: If the Port map loaded when Test init
        transport: Thrift socket object
        test_reboot_mode: reboot mode, which will be read from system env
        test_reboot_stage: reboot stage, which will be read from system env
        test_params: All the values passed via test-params if present
        interface_to_front_mapping: Config from port_map_file for the interface (local) to front(PTF) mapping
        protocol: Thrift protocol object
        client: RPC client which used in Thrift
    """

    def __init__(self, *args, **kwargs):
        """
        Init ThriftInterface.

        Set the following class attributes:
            port_map_loaded: If the Port map loaded when Test init
            transport: Thrift socket object
            test_reboot_mode: reboot mode, which will be read from system env
            test_reboot_stage: reboot stage, which will be read from system env
            test_params: All the values passed via test-params if present
            interface_to_front_mapping: Config from port_map_file for the interface (local) to front(PTF) mapping
            protocol: Thrift protocol object
            client: RPC client which used in Thrift
        """
        super().__init__(*args, **kwargs)
        self.port_map_loaded = False
        """
        If the Port map loaded when Test init
        """

        self.transport = None
        """
        Thrift socket object
        """

        self.test_reboot_mode = None
        """
        reboot mode, which will be read from system env
        """
        self.test_reboot_stage = None
        """
        reboot stage, which will be read from system env
        """

        self.interface_to_front_mapping = {}
        """
        Config from port_map_file for the interface (local) to front(PTF) mapping
        """

        self.test_params = None
        """
        All the values passed via test-params if present
        """

        self.protocol = None
        """
        Thrift protocol object
        """

        self.client = None
        """
        RPC client which used in Thrift
        """


    def setUp(self):
        super(ThriftInterface, self).setUp()
        self.interface_to_front_mapping = {}
        self.port_map_loaded = False
        """
        If the Port map loaded when Test init
        """

        self.transport = None
        """
        Thrift socket object
        """

        self.test_reboot_mode = None
        """
        reboot mode, which will be read from system env
        """
        self.test_reboot_stage = None
        """
        reboot stage, which will be read from system env
        """

        self.interface_to_front_mapping = {}
        """
        Config from port_map_file for the interface (local) to front(PTF) mapping
        """

        self.test_params = None
        """
        All the values passed via test-params if present
        """

        self.protocol = None
        """
        Thrift protocol object
        """

        self.client = None
        """
        RPC client which used in Thrift
        """


    def setUp(self, skip_reason = None):
        # First, before any SAI call. Note this is the setUp that runs: the
        # class defines setUp twice and Python keeps this one. It also cannot
        # live in __init__ -- ptf builds every test instance up front and only
        # then runs them, so the recorder would point at the last one built.
        module = self.__class__.__module__
        sai_capture.set_sink(None)
        sai_capture.set_case(module, self.__class__.__name__)
        sai_capture.configure_adapter(
            adapter, enabled=module not in PERF_MODULES)
        if skip_reason:
            print("SkipTest as {}".format(skip_reason))
            testutils.skipped_test_count = testutils.skipped_test_count + 1
            raise SkipTest(skip_reason)

        super(ThriftInterface, self).setUp()
        self.test_params = test_params_get()
        self.runtime_control = RuntimeControl(self.test_params)
        if get_platform() == 'ctc' and RUN_REG:
            kill_saiserver(self.runtime_control)
            print(f"killed\n" + "-"*50)
            time.sleep(10)
            pid = start_saiserver(self.runtime_control)
            print(f"saiserver start PID:{pid}")
        self.loadTestRebootMode()
        self.loadPortMap()
        self.createRpcClient()


    def loadTestRebootMode(self):
        """
        Get if test the reboot mode and what's the reboot mode need to be tested

        In reboot mode, test will run many times in different reboot stage.
        Tests in different stage might be different.

        Set the following class attributes:
            test_reboot_loaded - if the reboot mode already loaded
            test_reboot_mode - reboot mode
            test_reboot_stage - reboot stage, can be [setup|starting|post]
        """
        self.test_reboot_stage = None
        self.test_reboot_mode = 'cold'
        print("Reboot mode is: {}".format(self.test_reboot_mode))


    def tearDown(self):
        self.transport.close()
        super(ThriftInterface, self).tearDown()


    def loadPortMap(self):
        """
        Get and format port_map

        port_map_file is a port map with following lines format:
        [test_port_no]@[device_port_name]
        e.g.:
             0@Veth1
             1@Veth2
             2@Veth3  ...
        """
        if self.port_map_loaded:
            print("port_map already loaded")
            return

        if "port_map" in self.test_params:
            user_input = self.test_params['port_map']
            splitted_map = user_input.split(",")
            for item in splitted_map:
                iface_front_pair = item.split("@")
                self.interface_to_front_mapping[iface_front_pair[0]] =  \
                    iface_front_pair[1]
        elif "port_map_file" in self.test_params:
            user_input = self.test_params['port_map_file']
            with open(user_input, 'r') as map_file:
                for line in map_file:
                    if (line and (line[0] == '#' or
                                  line[0] == ';' or line[0] == '/')):
                        continue
                    iface_front_pair = line.split("@")
                    self.interface_to_front_mapping[iface_front_pair[0]] =  \
                        iface_front_pair[1].strip()

        self.port_map_loaded = True

    def createRpcClient(self):
        """
        Set up thrift client and contact RPC server
        """

        if 'thrift_server' in self.test_params:
            server = self.test_params['thrift_server']
        else:
            server = 'localhost'

        self.transport = TSocket.TSocket(server, _rpc_port(self.test_params))
        if get_thrift_version() == '0.14.1':
            self.transport = TTransport.TFramedTransport(self.transport)
        else:
            self.transport = TTransport.TBufferedTransport(self.transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(self.transport)

        self.client = sai_rpc.Client(self.protocol)
        self.transport.open()



class ThriftInterfaceDataPlane(ThriftInterface):
    """
    Sets up the thrift interface and dataplane

    class attributes:
        dataplane: Represent the dataplane used in test, pcap to manipulate the data
    """

    def __init__(self, *args, **kwargs):
        """
        Init ThriftInterfaceDataPlane

        Set the following class attributes:
            dataplane: Represent the dataplane used in test, pcap to manipulate the data
        """
        super().__init__(*args, **kwargs)
        self.dataplane = None
        """
        Represent the dataplane used in test, pcap to manipulate the data
        """


    def setUp(self, skip_reason = None):
        """
        Setup the ThriftInterfaceDataPlane.
        """
        super(ThriftInterfaceDataPlane, self).setUp(skip_reason = skip_reason)

        self.dataplane = ptf.dataplane_instance
        if self.dataplane is not None:
            self.dataplane.flush()
            if config['log_dir'] is not None:
                filename = os.path.join(config['log_dir'], str(self)) + ".pcap"
                self.dataplane.start_pcap(filename)


    def tearDown(self):
        if config['log_dir'] is not None:
            self.dataplane.stop_pcap()
        super(ThriftInterfaceDataPlane, self).tearDown()

    if get_platform() == 'cisco':
        class WrappedSaiThriftRouteEntryT(sai_thrift_route_entry_t_origin):
            def __init__(self, base_instance, *args, **kwargs):
                sig = inspect.signature(sai_thrift_route_entry_t_origin.__init__)
                bound_args = sig.bind(base_instance, *args, **kwargs)
                bound_args.apply_defaults()

                if 'switch_id' not in kwargs or kwargs['switch_id'] is None:
                    switch_id = base_instance.switch_id
                else:
                    switch_id = kwargs['switch_id']

                super().__init__(switch_id=switch_id, vr_id=kwargs.get('vr_id'), destination=kwargs.get('destination'))

        class WrappedSaiThriftNeighborEntryT(sai_thrift_neighbor_entry_t_origin):
            def __init__(self, base_instance, *args, **kwargs):
                sig = inspect.signature(sai_thrift_neighbor_entry_t_origin.__init__)
                bound_args = sig.bind(base_instance, *args, **kwargs)
                bound_args.apply_defaults()

                if 'switch_id' not in kwargs or kwargs['switch_id'] is None:
                    switch_id = base_instance.switch_id
                else:
                    switch_id = kwargs['switch_id']

                super().__init__(switch_id=switch_id, rif_id=kwargs.get('rif_id'), ip_address=kwargs.get('ip_address'))

        _current_sai_helper = None

        def sai_thrift_route_entry_t(*args, **kwargs):
            if _current_sai_helper is None:
                raise RuntimeError("sai_thrift_route_entry_t called before SaiHelper is initialized")
            return WrappedSaiThriftRouteEntryT(_current_sai_helper, *args, **kwargs)

        def sai_thrift_neighbor_entry_t(*args, **kwargs):
            if _current_sai_helper is None:
                raise RuntimeError("sai_thrift_neighbor_entry_t called before SaiHelper is initialized")
            return WrappedSaiThriftNeighborEntryT(_current_sai_helper, *args, **kwargs)

class SaiHelperBase(ThriftInterfaceDataPlane):
    """
    SAI test helper base class without initial switch ports setup

    Set the following class attributes:
        self.default_vlan_id
        self.default_vrf
        self.default_1q_bridge
        self.cpu_port_hdl
        self.active_ports_no - number of active ports
        self.system_port_no - number of system ports
        self.port_list - list of all active port objects
        self.portX objects for all active ports (where X is a port number)
        self.port_configer for config ports
    """

    platform = 'common'

    def __init__(self, *args, **kwargs):
        """
        Init the T0 Test Object.
        Set the following class attributes:
            dut: Dut object in test.
            servers: Simulating the server Objects in Test.
            t1_list: Simulating the T1 objects in test

        """
        super().__init__(*args, **kwargs)
        self.default_vlan_id = None
        self.default_vrf = None
        self.default_1q_bridge = None
        self.cpu_port_hdl = None
        self.active_ports_no: int = 0
        """
        Device active ports.
        """
        self.system_port_no: int = 0
        """
        Device system ports.
        """

        self.active_port_obj_list: List['Port'] = []
        self.port_id_list = []
        """
        Device active port obj list.
        Those ports might more than actual port in testing.
        For ports in testing, please use port_obj_list.
        """
        self.port_list: List = []
        self.port_configer: PortConfiger = None
        self.config_db_loader: ConfigDBLoader = None
        self.port_config_ini_loader: PortConfigInILoader = None
        self.dev_port_list = []
        self.port_lane_map_list = {}
        # TODO: Below two attributes should be move to port_configer
        self.ports_config = None
        """
        ports_config dict, use to compatiable with old data module
        """
        self.bridge_port_list = []
        """
        Bridge port list
        """
        self.def_bridge_port_list = []
        self.def_vlan_member_list = []

        # Test result collection (initialized in setUp)
        self._result_collector = None
        self._spec_registry = None

    def run_host(self, argv, timeout_s=None, check=True):
        return self.runtime_control.run_remote(
            argv, timeout_s=timeout_s, check=check)

    def run_host_container(self, argv,
                           container_parameter='host_control_container',
                           timeout_s=None, check=True):
        return self.runtime_control.run_container(
            argv, container_parameter=container_parameter,
            timeout_s=timeout_s, check=check)

    def _init_result_collector(self):
        """Initialize test result collector with metadata."""
        output_dir = self.test_params.get(
            'result_output_dir', '/tmp/sai_test_results')
        self._result_collector = TestResultCollector(
            test_class_name=self.__class__.__name__,
            test_module_name=self.__class__.__module__,
            output_dir=output_dir
        )
        self._result_collector.start_time = time.time()
        sai_capture.set_sink(self._result_collector.record_attr_row)

        # Load spec registry (authoritative unit / result_type / direction)
        self._spec_registry = SpecRegistry()

        self._result_collector.set_metadata(
            platform=get_platform(),
            chip=None,
        )

    def _query_sai_version(self):
        """Best-effort SAI version for metadata; return None when unknown."""
        return getattr(self, '_sai_api_version', None)

    def _record_measurement(self, m):
        if self._result_collector:
            self._result_collector.add_spec_result(
                spec_name=m.spec_name,
                operation=m.operation,
                value=m.value,
                threshold=m.threshold,
                details=m.details)

    def record_spec(self, spec_name, operation, value=None, details=None,
                    threshold=None, **legacy):
        """Record one v2 spec measurement fact.

        `spec_registry.json` owns unit, result type and comparison direction.
        `details` may contain attempted_count, completed_count, observed_count,
        duration_seconds, scenario, or error.

        Legacy keyword arguments are translated during the producer migration so
        existing scale tests keep emitting v2 JSON.
        """
        if self._spec_registry and not self._spec_registry.is_known(spec_name):
            raise AssertionError(
                "spec '%s' is not in spec_registry.json; register it first."
                % spec_name)
        if value is None and 'actual_value' in legacy:
            value = legacy['actual_value']
        if threshold is None:
            threshold = legacy.get('baseline')
        details = dict(details or legacy.get('extra') or {})
        for old_key, new_key in (
                ('total_count', 'attempted_count'),
                ('success_route_cnt', 'completed_count'),
                ('success_count', 'completed_count'),
                ('fail_count', 'failed_count'),
                ('bulk_size', 'batch_size'),
                ('order', 'scenario')):
            if old_key in details and new_key not in details:
                details[new_key] = details.pop(old_key)
        count = legacy.get('count')
        duration = legacy.get('duration')
        result_type = (self._spec_registry.get_result_type(spec_name)
                       if self._spec_registry else 'performance')
        if duration is not None:
            details['duration_seconds'] = round(duration, 3)
        if result_type == 'fill_rate':
            if count is not None:
                details['attempted_count'] = count
            completed = details.pop('success_route_cnt',
                                    details.pop('success_count', None))
            if completed is not None:
                details['completed_count'] = completed
            if 'order' in details:
                details['scenario'] = details.pop('order')
        elif '_counter_' in spec_name:
            if count is not None:
                details['observed_count'] = count
        elif result_type == 'performance' and count is not None:
            direction = (self._spec_registry.get_direction(spec_name)
                         if self._spec_registry else 'higher_better')
            key = 'observed_count' if direction == 'lower_better' \
                else 'completed_count'
            details[key] = count
        normalized_operation = operation or None
        if not self._result_collector:
            return
        self._record_measurement(Measurement(
            spec_name, normalized_operation, value, details, threshold))

    def probe_get_capability(self, spec_name, getter, expected):
        """Probe a get-capability without ever failing the test case.

        Records actual_value=1 when the read-back equals `expected`, else 0.
        Any exception (chip does not support the get, thrift error, ...) is
        swallowed and recorded as 0 -- a chip is allowed not to support get,
        so this MUST NOT mark the test as failed (design 6.2 / user decision:
        "get 失败不影响用例结果").

        Args:
            spec_name: attr full name, e.g. SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID
            getter: zero-arg callable returning the read-back value
            expected: the value that was programmed (or the known-correct
                      value for READ_ONLY attrs, e.g. the address family of
                      the route the case itself created)
        """
        try:
            got = getter()
            supported = 1 if got == expected else 0
            extra = {} if supported else {"got": str(got),
                                          "expected": str(expected)}
            self.record_spec(spec_name, "get", count=1,
                             actual_value=supported, extra=extra)
        except Exception as e:  # noqa - intentional broad catch, see docstring
            self.record_spec(spec_name, "get", count=1, actual_value=0,
                             extra={"error": str(e)})

    def mark_test_fail(self, error_message):
        """Mark the overall test as failed with error message.

        Call this in exception handlers to ensure failure is recorded
        in the result JSON.

        Args:
            error_message: Description of the failure
        """
        if self._result_collector:
            self._result_collector.mark_fail(error_message)

    def _finalize_result(self):
        """Finalize and write result JSON file."""
        if self._result_collector:
            self._result_collector.end_time = time.time()
            try:
                self._result_collector.write_json()
            except Exception as e:
                print(f"[ResultCollector] Warning: failed to write result "
                      f"JSON: {e}")

    def get_default_switch_attr(self):
        """
        Get default switch attr.
        includes:
            system_port_no: number_of_system_ports
            active_ports_no: number_of_active_ports

        """
        print("Ignore all the expect error code and exception captures.")
        ignore_api_errors()

        attr = sai_thrift_get_switch_attribute(
            self.client, number_of_system_ports=True)
        number_of_system_ports = 0
        if attr and 'number_of_system_ports' in attr:
            number_of_system_ports = attr['number_of_system_ports']
        self.system_port_no = number_of_system_ports
        print("Get number_of_system_ports {}".format(self.system_port_no))

        attr = sai_thrift_get_switch_attribute(
            self.client, number_of_active_ports=True)
        self.active_ports_no = attr['number_of_active_ports']
        print("Get number_of_active_ports {}".format(self.active_ports_no))

        print("Restore all the expect error code and exception captures.")
        restore_api_error_code()


    def set_logger_name(self):
        """
        Set Logger name as filename:classname
        """

        file_name = inspect.getfile(self.__class__)
        class_name = self.__class__.__name__
        logger_name = "{}:{}".format(file_name, class_name)
        LogConfig.set_logging(loggerName = logger_name)


    def get_active_port_list(self):
        '''
        Method to get the active port list base on number_of_active_ports

        Sets the following class attributes:
            self.port_list - list of all active port objects
            self.portX objects for all active ports
        '''

        # get port_list and portX objects
        attr = sai_thrift_get_switch_attribute(
            self.client, number_of_active_ports=True)
        self.active_ports_no = attr['number_of_active_ports']
        attr = sai_thrift_get_switch_attribute(
            self.client, port_list=sai_thrift_object_list_t(
                idlist=[], count=self.active_ports_no))
        self.assertEqual(self.active_ports_no, attr['port_list'].count)
        self.port_list = attr['port_list'].idlist

        # print(f"self.port_list:{self.port_list}")

        # get active from port_config.ini
        port_obj_list_with_lane = self.port_configer.get_port_default_lane()
        self.port_id_list = self.port_configer.get_lane_sorted_port_list(port_obj_list_with_lane)
        self.port_list = self.port_id_list
        self.port_configer.generate_port_obj_list_by_interface_config()

        #Gets self.portX objects for all active ports
        for i, _ in enumerate(self.port_list):
            setattr(self, 'port%s' % i, self.port_list[i])
        # print(f"self.port_list after filter:{self.port_list}")

        # get port_lane_map_list
        self.port_configer.set_port_attribute(self.port_configer.test_obj.active_port_obj_list)
        self.port_lane_map_list=self.port_configer.get_port_attribute(self.port_configer.test_obj.active_port_obj_list)

    def config_port(self):
        '''
        Method to config the ports.
        '''
        # Bring the ports up on every platform, brcm included. brcm used to be
        # excluded here on the assumption that brcm always runs
        # BrcmSaiHelper.config_port (which does its own bring-up). That holds
        # for PlatformSaiHelper-derived classes (they are rebased onto
        # BrcmSaiHelper) but NOT for SaiHelperSimplified, which inherits
        # SaiHelperBase directly and reaches THIS base implementation. With
        # brcm skipped, SaiHelperSimplified left port0/port1 admin-down, so its
        # RIF-based L3 forwarding failed before any test logic ran. BrcmSaiHelper
        # fully overrides config_port and never calls this version, so bringing
        # the ports up here cannot double up for the rebased classes -- it only
        # fixes the SaiHelperSimplified path. turn_up_and_check_ports has a
        # self-contained brcm branch (admin_state=True + oper-status polling).
        self.turn_up_and_check_ports()
        # get default 1Q bridge OID
        self.get_default_1q_bridge_id()

        #remove all default 1Q bridge port
        self.reset_1q_bridge_ports()


    def turn_up_and_check_ports(self):
        '''
        Method to turn up the ports.
        In case some device not init the port after start the switch.

        Args:
            port_list - list of all active port objects
        '''
        #TODO check if this is common behivor or specified after check on more platform
        if get_platform() == 'brcm' or get_platform() == 'ctc':
            print("Brcm platform, need to Turn up port with admin_state=True")
            self.port_configer.set_port_attribute(self.port_configer.test_obj.active_port_obj_list)
            self.port_lane_map_list=self.port_configer.get_port_attribute(self.port_configer.test_obj.active_port_obj_list)
            for index, oid in enumerate(self.port_list):
                sai_thrift_set_port_attribute(
                            self.client,
                            oid,
                            admin_state=True)
        elif get_platform() == 'clx':
            print("Clounix platform, need to Turn up port with admin_state=True")
            # get all device ports lane
            port_obj_list_with_lane = self.port_configer.get_port_default_lane()
            self.port_lane_map_list = {}
            for index, port in enumerate(port_obj_list_with_lane):
                self.port_lane_map_list[port.default_lane_list[0]]= {
                    'port': port.oid
                    }
            for index, oid in enumerate(self.port_list):
                sai_thrift_set_port_attribute(
                            self.client,
                            oid,
                            admin_state=True)
        else:
            print("For Common platform, Only check Port status.")


        # For brcm devices, need to init and setup the ports at once after start the switch.
        retries = 10
        down_port_list = []
        for index, oid in enumerate(self.port_list):
            if get_platform() == 'cisco' or get_platform() == 'ctc':
                sai_thrift_set_port_attribute(
                    self.client,
                    port_oid=oid,
                    admin_state=True)
            port_attr = sai_thrift_get_port_attribute(
                self.client, oid, oper_status=True)
            print("Turn up port {:x}".format(oid))
            port_up = True
            if port_attr['oper_status'] != SAI_PORT_OPER_STATUS_UP:
                port_up = False
                for num_of_tries in range(retries):
                    port_attr = sai_thrift_get_port_attribute(
                        self.client, oid, oper_status=True)
                    if port_attr['oper_status'] == SAI_PORT_OPER_STATUS_UP:
                        port_up = True
                        break
                    time.sleep(5)
                    print("port {}:{} is not up, status: {}. Retry. Waiting for Admin State Up.".format(
                        index, oid, port_attr['oper_status']))
                    if get_platform() == 'brcm' or get_platform() == 'cisco' or get_platform() == 'ctc':
                        print("Retry turning up port with admin_state=True")
                        sai_thrift_set_port_attribute(
                                    self.client,
                                    oid,
                                    admin_state=True)
                    else:
                        print("For Common platform, Waitng...")
            if not port_up:
                down_port_list.append(index)
        if down_port_list:
            print("Ports {} are  down after retries.".format(down_port_list))


    def shell(self):
        '''
        Method use to start a sai shell in a thread.
        '''
        def start_shell():
            sai_thrift_set_switch_attribute(self.client, switch_shell_enable=True)
        thread = Thread(target = start_shell)
        thread.start()


    def recreate_ports(self):
        '''
        Recreate the port base on file specified in 'port_config_ini' param.
        '''
        #TODO check if this is common behivor or specified after check on more platform
        if 'port_config_ini' in self.test_params:
            if 'createPorts_has_been_called' not in config:
                self.createPorts()
                # check if ports became UP
                #self.checkPortsUp()
                config['createPorts_has_been_called'] = 1


    def get_default_1q_bridge_id(self):
        '''
        Gets default 1q bridge 1d, set it to class attribute 'default_1q_bridge'.

        Sets the following class attributes:

            self.default_1q_bridge - default_1q_bridge_id
        '''

        print("Get default 1Q bridge id...")
        attr = sai_thrift_get_switch_attribute(
            self.client, default_1q_bridge_id=True)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
        self.default_1q_bridge = attr['default_1q_bridge_id']


    def reset_1q_bridge_ports(self):
        '''
        Reset all the 1Q bridge ports.
        Needs the following class attributes:
            self.default_1q_bridge - default_1q_bridge oid

            self.active_ports_no - number of active ports

            self.portX objects for all active ports
        '''
        #TODO check if this is common behivor or specified after check on more platform
        #TODO move this function to CommonSaiHelper
        if get_platform() in ['cisco','ctc' ,'clx']:
            bridge_id = self.default_1q_bridge
            self.def_bridge_port_list \
                = self.get_all_bridge_ports(bridge_id)
            self.remove_all_bridge_ports()
            return
        if get_platform() == 'brcm':
            # BRCM leaks the default test topology (VLANs + bridge ports)
            # across tests: remove_switch() is a no-op SDK bug, tearDown only
            # cleans hostifs, and a crashed setUp leaves objects half-built
            # whose OIDs are then lost. Residual objects make the next test's
            # create_bridge_ports / create_vlan_with_members fail with -6
            # (ITEM_ALREADY_EXISTS). Purge them here so every setUp self-heals,
            # independent of the previous test's teardown. Keep the default
            # VLAN and the 1Q_ROUTER bridge port intact.
            self._reset_brcm_default_topology()
            return
        print("For Common platform, expecting bridge ports not been created by default.")

    def _reset_brcm_default_topology(self):
        '''
        Purge the residual default test topology on BRCM so each setUp starts
        clean, regardless of how the previous test tore down (or crashed).

        Two stages, in order (verified on TH6):
          1. Remove residual non-default VLANs. Their OIDs are lost after a
             crashed setUp, but BRCM encodes the VLAN OID deterministically as
             (default_vlan_id & ~0xffff) | vid, so we derive and remove each
             candidate vid. remove() returning SUCCESS means the VLAN existed
             and was removed (BRCM drops its members with it); any error code
             means it was absent -- both are fine. The default VLAN (vid 1) is
             never touched.
          2. Remove SAI_BRIDGE_PORT_TYPE_PORT bridge ports from the default 1Q
             bridge, keeping the 1Q_ROUTER port.

        VLANs are cleared before bridge ports so no dangling VLAN members are
        left behind. Defensive throughout: a failed enumerate/remove must not
        crash setUp.
        '''
        bridge_id = self.default_1q_bridge
        if not bridge_id:
            return

        # Stage 1: residual non-default VLANs (skip default vid 1).
        vlan_oid_base = self.default_vlan_id & ~0xffff
        vlan_removed = 0
        for vid in range(2, 4095):
            sai_thrift_remove_vlan(self.client, vlan_oid_base | vid)
            if self.status() == SAI_STATUS_SUCCESS:
                vlan_removed += 1

        # Stage 2: residual PORT-type bridge ports.
        buf_size = self.system_port_no + self.active_ports_no + 8
        attr = sai_thrift_get_bridge_attribute(
            self.client, bridge_oid=bridge_id,
            port_list=sai_thrift_object_list_t(
                idlist=[0] * buf_size, count=buf_size))
        bp_total = 0
        bp_removed = 0
        if attr and attr.get('port_list') is not None:
            bp_list = list(attr['port_list'].idlist)
            bp_total = len(bp_list)
            for bp in bp_list:
                type_attr = sai_thrift_get_bridge_port_attribute(
                    self.client, bp, type=True)
                bp_type = type_attr.get('type') if type_attr else None
                if bp_type == SAI_BRIDGE_PORT_TYPE_PORT:
                    sai_thrift_remove_bridge_port(self.client, bp)
                    if self.status() == SAI_STATUS_SUCCESS:
                        bp_removed += 1
        else:
            print("BRCM topology reset: unable to read bridge port_list")

        print("BRCM topology reset: removed {} residual VLANs, "
              "{} of {} bridge ports".format(
                  vlan_removed, bp_removed, bp_total))

    def check_cpu_port_hdl(self):
        """
        Checks cpu port handler.
        Expect the cpu_port_hdl equals to qos_queue port id, number_of_queues in qos equals to queue index.
        Needs the following class attributes:
            self.cpu_port_hdl - cpu_port_hdl id
        Seds the following class attributes:
            self.cpu_queueX - cpu queue id
        """
        #TODO move this function to CommonSaiHelper
        attr = sai_thrift_get_port_attribute(self.client,
                                             self.cpu_port_hdl,
                                             qos_number_of_queues=True)
        num_queues = attr['qos_number_of_queues']
        q_list = sai_thrift_object_list_t(count=num_queues)
        attr = sai_thrift_get_port_attribute(self.client,
                                             self.cpu_port_hdl,
                                             qos_queue_list=q_list)
        for queue in range(0, num_queues):
            queue_id = attr['qos_queue_list'].idlist[queue]
            setattr(self, 'cpu_queue%s' % queue, queue_id)
            q_attr = sai_thrift_get_queue_attribute(
                self.client,
                queue_id,
                port=True,
                index=True,
                parent_scheduler_node=True)
            self.assertEqual(queue, q_attr['index'])
            self.assertEqual(self.cpu_port_hdl, q_attr['port'])

    def start_switch(self):
        """
        Start switch.
        """
        self.switch_id = sai_thrift_create_switch(
        self.client, init_switch=True, src_mac_address=ROUTER_MAC,
            port_state_change_notify=None, fdb_event_notify=None,
            switch_shutdown_request_notify=None,
            switch_state_change_notify=None)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)


    def warm_start_switch(self):
        """
        Warm start switch.
        """
        self.switch_id = sai_thrift_create_switch(
        self.client, init_switch=True, warm_recover=True)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)


    def set_accepted_exception(self):
        """
        Set accepted exceptions.
        """
        adapter.CATCH_EXCEPTIONS=True


    def get_default_vlan(self):
        """
        Get default vlan.

        Returns:
            default_vlan_id
        """
        print("Get default vlan...")
        def_attr = sai_thrift_get_switch_attribute(self.client, default_vlan_id=True)
        self.assertNotEqual(def_attr['default_vlan_id'], 0)
        return def_attr['default_vlan_id']


    def get_vlan_member(self, vlan_id):
        """
        Get vlan member by vlan id.

        Args:
            vlan_id: vlan id

        Returns:
            list: vlan member oid list
        """
        vlan_member_size = self.system_port_no + self.active_ports_no
        vlan_member_list = sai_thrift_object_list_t(count=vlan_member_size)
        mbr_list = sai_thrift_get_vlan_attribute(self.client, vlan_id, member_list=vlan_member_list)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
        return mbr_list['SAI_VLAN_ATTR_MEMBER_LIST'].idlist


    def remove_vlan_members(self, vlan_members):
        """
        Remove vlan members.

        Args:
            vlan_members: vlan member oids
        """
        for vlan_member in vlan_members:
            status = sai_thrift_remove_vlan_member(self.client, vlan_member)
            self.assertEqual(status, SAI_STATUS_SUCCESS)


    def remove_default_vlan(self):
        """
        Remove default vlan
        """
        if 'target' in self.test_params:
            if self.test_params['target'] == 'bmv2':
                return
        members = self.get_vlan_member(self.default_vlan_id)
        self.remove_vlan_members(members)


    def setUp(self, skip_reason = None):
        super(SaiHelperBase, self).setUp(skip_reason = skip_reason)
        self._init_result_collector()

        if 'config_db_json' in self.test_params:
            self.config_db_loader = ConfigDBLoader(self.test_params['config_db_json'])
        else:
            self.config_db_loader = ConfigDBLoader()
        self.ports_config = self.config_db_loader.get_port_config()

        if 'port_config_ini' in self.test_params:
            self.port_config_ini_loader = PortConfigInILoader(self.test_params['port_config_ini'])
        else:
            self.port_config_ini_loader = PortConfigInILoader()
        self.port_config_ini_loader.parse_port_config()

        self.port_configer = PortConfiger(self)
        self.def_bridge_port_list = []
        self.def_bridge_port_list = []
        self.def_vlan_member_list = []
        self.set_logger_name()
        self.set_accepted_exception()
        self.getSwitchPorts()
        # initialize switch
        self.start_switch()
        if get_platform() == 'cisco':
            global _current_sai_helper
            _current_sai_helper = self
            global sai_thrift_route_entry_t
            global sai_thrift_neighbor_entry_t
            self.original_sai_thrift_route_entry_t = sai_thrift_route_entry_t_origin
            self.original_sai_thrift_neighbor_entry_t = sai_thrift_neighbor_entry_t_origin
            sai_thrift_route_entry_t = lambda *args, **kwargs: WrappedSaiThriftRouteEntryT(self, *args, **kwargs)
            sai_thrift_neighbor_entry_t = lambda *args, **kwargs: WrappedSaiThriftNeighborEntryT(self, *args, **kwargs)
        self.get_default_switch_attr()

        # debug=False: skip the ~30-line available-resources dump printed every test.
        self.switch_resources = self.saveNumberOfAvaiableResources(debug=False)

        # get default vlan
        self.default_vlan_id = self.get_default_vlan()

        # remove default vlan
        self.remove_default_vlan()

        self.recreate_ports()

        # get number of active ports
        self.get_active_port_list()

        # get default vrf
        attr = sai_thrift_get_switch_attribute(
            self.client, default_virtual_router_id=True)
        self.default_vrf = attr['default_virtual_router_id']
        self.assertNotEqual(self.default_vrf, 0)

        if 'test_case' in self.test_params:
            if self.test_params['test_case'] == 'Counter':
                self.get_default_1q_bridge_id()
                #remove all default 1Q bridge port
                self.reset_1q_bridge_ports()
            else:
                self.config_port()
        else:
            self.config_port()

        # get cpu port
        attr = sai_thrift_get_switch_attribute(self.client, cpu_port=True)
        self.cpu_port_hdl = attr['cpu_port']
        self.assertNotEqual(self.cpu_port_hdl, 0)

        # get cpu port queue handles
        self.check_cpu_port_hdl()

        # due to unknown reasons, can not create default ipv6 router entry
        # therefore create a new vrf as default vrf
        if get_platform() != 'ctc':
            self.default_vrf = sai_thrift_create_virtual_router(self.client)

        self._result_collector.set_metadata(
            sai_version=self._query_sai_version(),
            port_count=len(self.port_list),
        )

        print("Finish SaiHelperBase setup")


    def tearDown(self):
        try:
            for port in self.port_list:
                clear_counter(
                    self, sai_thrift_clear_port_stats, port)
                sai_thrift_set_port_attribute(
                    self.client, port, port_vlan_id=0)
            # created default vrf need to be removed when test done
            sai_thrift_remove_virtual_router(self.client, self.default_vrf)
            #Todo: Remove this condition after brcm's remove_switch issue fixed
            if get_platform() == 'brcm':
                return
            # always failed in this step
            # self.assertTrue(self.verifyNumberOfAvaiableResources(
            #     self.switch_resources, debug=False))
        finally:
            # Always write result JSON, even on failure or crash
            self._finalize_result()
            super(SaiHelperBase, self).tearDown()


    def createPorts(self):
        """
        Create ports after reading from port config file
        """
        def fec_str_to_int(fec):
            """
            Convert fec string to SAI enum

            Args:
                fec (string): fec string from port_config

            Returns:
                int: SAI enum value
            """
            fec_dict = {
                'rs': SAI_PORT_FEC_MODE_RS,
                'fc': SAI_PORT_FEC_MODE_FC
            }
            return fec_dict.get(fec, SAI_PORT_FEC_MODE_NONE)

        # delete the existing ports
        attr = sai_thrift_get_switch_attribute(
            self.client, number_of_active_ports=True)
        self.active_ports_no = attr['number_of_active_ports']
        attr = sai_thrift_get_switch_attribute(
            self.client, port_list=sai_thrift_object_list_t(
                idlist=[], count=self.active_ports_no))
        if self.active_ports_no:
            self.port_list = attr['port_list'].idlist
            for port in self.port_list:
                sai_thrift_remove_port(self.client, port)

        # add new ports from port config file
        ports_config = self.port_config_ini_loader.ports_config
        for name, port in ports_config.items():
            print("Creating port: %s" % name)
            fec_mode = fec_str_to_int(port.get('fec', None))
            auto_neg_mode = True if port.get(
                'autoneg', "").lower() == "on" else False
            sai_list = sai_thrift_u32_list_t(
                count=len(port['lanes']), uint32list=port['lanes'])
            sai_thrift_create_port(self.client,
                                   hw_lane_list=sai_list,
                                   fec_mode=fec_mode,
                                   auto_neg_mode=auto_neg_mode,
                                   speed=port['speed'],
                                   admin_state=True)


    def checkPortsUp(self, timeout=30):
        """
        Wait for all ports to be UP
        This may be required while testing on hardware
        The test fails if all ports are not UP after timeout

        Args:
            timeout (int): port verification timeout in sec
        """
        allup = False
        timer_start = time.time()

        while allup is False and time.time() - timer_start < timeout:
            allup = True
            for port in self.port_list:
                attr = sai_thrift_get_port_attribute(
                    self.client, port, oper_status=True)
                if attr['oper_status'] != SAI_SWITCH_OPER_STATUS_UP:
                    allup = False
                    break
            if allup:
                break
            time.sleep(5)

        self.assertTrue(allup)

    def getSwitchPorts(self):
        """
        Get device port numbers
        """
        dev_no = 0
        for _, port, _ in config['interfaces']:
            # remove after DASH will be introduced as confuses with "dev" prefix
            # added tg as a shortcut for "traffic generator"
            setattr(self, 'dev_port%d' % dev_no, port)
            self.dev_port_list.append(port)
            setattr(self, 'tg%d' % dev_no, port)
            dev_no += 1

    def printNumberOfAvaiableResources(self, resources_dict):
        """
        Prints numbers of available resources

        Args:
            resources_dict (dict): a dictionary with resources numbers
        """

        print("***** Number of available resources *****")
        for key, value in resources_dict.items():
            print(key, ": ", value)

    def saveNumberOfAvaiableResources(self, debug=False):
        """
        Save number of available resources
        This allows to verify if all the test objects were removed

        Args:
            debug (bool): enables debug option
        Return:
            dict: switch_resources dictionary with available resources
        """
        if get_platform() == "cisco":
            switch_resources = sai_thrift_get_switch_attribute(
                self.client,
                available_ipv4_route_entry=True,
                available_ipv6_route_entry=True,
                available_ipv4_nexthop_entry=True,
                available_ipv6_nexthop_entry=True,
                available_ipv4_neighbor_entry=True,
                available_ipv6_neighbor_entry=True,
                available_next_hop_group_entry=True,
                available_next_hop_group_member_entry=True,
                available_fdb_entry=True,
                number_of_ecmp_groups=True,
                ecmp_members=True)
        elif get_platform() == 'clx':
            attr = sai_thrift_get_switch_attribute(
                self.client,
                qos_max_number_of_scheduler_group_hierarchy_levels=True,
                max_acl_action_count=True,
                number_of_active_ports=True)
            scheduler_group_hierarchy_levels_count = attr["qos_max_number_of_scheduler_group_hierarchy_levels"]
            max_acl_action_count = attr["max_acl_action_count"]
            number_of_active_ports= attr["number_of_active_ports"]
            switch_resources = sai_thrift_get_switch_attribute(
                self.client,
                available_ipv4_route_entry=True,
                available_ipv6_route_entry=True,
                available_ipv4_nexthop_entry=True,
                available_ipv6_nexthop_entry=True,
                available_ipv4_neighbor_entry=True,
                available_ipv6_neighbor_entry=True,
                available_next_hop_group_entry=True,
                available_next_hop_group_member_entry=True,
                available_fdb_entry=True,
                available_ipmc_entry=True,
                available_snat_entry=True,
                available_dnat_entry=True,
                number_of_ecmp_groups=True,
                ecmp_members=True,
                available_acl_table=sai_thrift_acl_resource_t(stage=SAI_SWITCH_ATTR_ACL_STAGE_INGRESS),
                number_of_active_ports=True,
                port_max_mtu=True,
                cpu_port=True,
                max_virtual_routers=True,
                fdb_table_size=True,
                l3_neighbor_table_size=True,
                l3_route_table_size=True,
                lag_members=True,
                number_of_lags=True,
                number_of_unicast_queues=True,
                number_of_multicast_queues=True,
                number_of_queues=True,
                number_of_cpu_queues=True,
                acl_table_minimum_priority=True,
                acl_table_maximum_priority=True,
                acl_entry_minimum_priority=True,
                acl_entry_maximum_priority=True,
                default_vlan_id=True,
                default_stp_inst_id=True,
                max_stp_instance=True,
                default_virtual_router_id=True,
                default_1q_bridge_id=True,
                qos_max_number_of_traffic_classes=True,
                qos_max_number_of_scheduler_group_hierarchy_levels=True,
                qos_max_number_of_scheduler_groups_per_hierarchy_level =
                    sai_thrift_u32_list_t(count=scheduler_group_hierarchy_levels_count,uint32list=[]),
                qos_max_number_of_childs_per_scheduler_group=True,
                total_buffer_size=True,
                ingress_buffer_pool_num=True,
                egress_buffer_pool_num=True,
                ecmp_hash=True,
                lag_hash=True,
                max_acl_action_count=True,
                max_acl_range_count=True,
                acl_capability=sai_thrift_acl_capability_t(
                    action_list=sai_thrift_s32_list_t(int32list=[], count=max_acl_action_count)),
                max_mirror_session=True,
                default_trap_group=True,
                acl_stage_ingress=sai_thrift_acl_capability_t(
                    action_list=sai_thrift_s32_list_t(int32list=[], count=max_acl_action_count)),
                acl_stage_egress=sai_thrift_acl_capability_t(
                    action_list=sai_thrift_s32_list_t(int32list=[], count=max_acl_action_count)),
                counter_refresh_interval=True,
                port_list=sai_thrift_object_list_t(idlist=[], count=number_of_active_ports))
        else:
            switch_resources = sai_thrift_get_switch_attribute(
                self.client,
                available_ipv4_route_entry=True,
                available_ipv6_route_entry=True,
                available_ipv4_nexthop_entry=True,
                available_ipv6_nexthop_entry=True,
                available_ipv4_neighbor_entry=True,
                available_ipv6_neighbor_entry=True,
                available_next_hop_group_entry=True,
                available_next_hop_group_member_entry=True,
                available_fdb_entry=True,
                available_ipmc_entry=True,
                available_snat_entry=True,
                available_dnat_entry=True,
                available_double_nat_entry=True,
                number_of_ecmp_groups=True,
                ecmp_members=True)

        if debug:
            self.printNumberOfAvaiableResources(switch_resources)

        return switch_resources

    def verifyNumberOfAvaiableResources(self, init_resources, debug=False):
        """
        Verify number of available resources

        Args:
            init_resources (dict): a dictionary with initial resources numbers
            debug (bool): enable debug option

        Returns:
            bool: True if the numbers of resources are the same as before tests
        """
        if get_platform() == 'cisco':
            available_resources = sai_thrift_get_switch_attribute(
                self.client,
                available_ipv4_route_entry=True,
                available_ipv6_route_entry=True,
                available_ipv4_nexthop_entry=True,
                available_ipv6_nexthop_entry=True,
                available_ipv4_neighbor_entry=True,
                available_ipv6_neighbor_entry=True,
                available_next_hop_group_entry=True,
                available_next_hop_group_member_entry=True,
                available_fdb_entry=True,
                number_of_ecmp_groups=True,
                ecmp_members=True)
        elif get_platform() == 'clx':
            attr = sai_thrift_get_switch_attribute(
                self.client,
                qos_max_number_of_scheduler_group_hierarchy_levels=True,
                max_acl_action_count=True,
                number_of_active_ports=True)
            scheduler_group_hierarchy_levels_count = attr["qos_max_number_of_scheduler_group_hierarchy_levels"]
            max_acl_action_count = attr["max_acl_action_count"]
            number_of_active_ports= attr["number_of_active_ports"]
            available_resources = sai_thrift_get_switch_attribute(
                self.client,
                available_ipv4_route_entry=True,
                available_ipv6_route_entry=True,
                available_ipv4_nexthop_entry=True,
                available_ipv6_nexthop_entry=True,
                available_ipv4_neighbor_entry=True,
                available_ipv6_neighbor_entry=True,
                available_next_hop_group_entry=True,
                available_next_hop_group_member_entry=True,
                available_fdb_entry=True,
                available_ipmc_entry=True,
                available_snat_entry=True,
                available_dnat_entry=True,
                number_of_ecmp_groups=True,
                ecmp_members=True,
                available_acl_table=sai_thrift_acl_resource_t(stage=SAI_SWITCH_ATTR_ACL_STAGE_INGRESS),
                number_of_active_ports=True,
                port_max_mtu=True,
                cpu_port=True,
                max_virtual_routers=True,
                fdb_table_size=True,
                l3_neighbor_table_size=True,
                l3_route_table_size=True,
                lag_members=True,
                number_of_lags=True,
                number_of_unicast_queues=True,
                number_of_multicast_queues=True,
                number_of_queues=True,
                number_of_cpu_queues=True,
                acl_table_minimum_priority=True,
                acl_table_maximum_priority=True,
                acl_entry_minimum_priority=True,
                acl_entry_maximum_priority=True,
                default_vlan_id=True,
                default_stp_inst_id=True,
                max_stp_instance=True,
                default_virtual_router_id=True,
                default_1q_bridge_id=True,
                qos_max_number_of_traffic_classes=True,
                qos_max_number_of_scheduler_group_hierarchy_levels=True,
                qos_max_number_of_scheduler_groups_per_hierarchy_level =
                    sai_thrift_u32_list_t(count=scheduler_group_hierarchy_levels_count,uint32list=[]),
                qos_max_number_of_childs_per_scheduler_group=True,
                total_buffer_size=True,
                ingress_buffer_pool_num=True,
                egress_buffer_pool_num=True,
                ecmp_hash=True,
                lag_hash=True,
                max_acl_action_count=True,
                max_acl_range_count=True,
                acl_capability=sai_thrift_acl_capability_t(
                    action_list=sai_thrift_s32_list_t(int32list=[], count=max_acl_action_count)),
                max_mirror_session=True,
                default_trap_group=True,
                acl_stage_ingress=sai_thrift_acl_capability_t(
                    action_list=sai_thrift_s32_list_t(int32list=[], count=max_acl_action_count)),
                acl_stage_egress=sai_thrift_acl_capability_t(
                    action_list=sai_thrift_s32_list_t(int32list=[], count=max_acl_action_count)),
                counter_refresh_interval=True,
                port_list=sai_thrift_object_list_t(idlist=[], count=number_of_active_ports))
        else:
            available_resources = sai_thrift_get_switch_attribute(
                self.client,
                available_ipv4_route_entry=True,
                available_ipv6_route_entry=True,
                available_ipv4_nexthop_entry=True,
                available_ipv6_nexthop_entry=True,
                available_ipv4_neighbor_entry=True,
                available_ipv6_neighbor_entry=True,
                available_next_hop_group_entry=True,
                available_next_hop_group_member_entry=True,
                available_fdb_entry=True,
                available_ipmc_entry=True,
                available_snat_entry=True,
                available_dnat_entry=True,
                available_double_nat_entry=True,
                number_of_ecmp_groups=True,
                ecmp_members=True)

        for key, value in available_resources.items():
            if value != init_resources[key]:
                if debug:
                    print("Number of %s incorrect! Current value: %d, Init value: %d" % (key, value, init_resources[key]))
                return False

        return True

    @staticmethod
    def status():
        """
        Returns the last operation status.

        Returns:
            int: sai call result
        """
        return adapter.status

    @staticmethod
    def saiWaitFdbAge(timeout):
        """
        Wait for fdb entry to ageout

        Args:
            timeout (int): Timeout value in seconds
        """
        print("Waiting for fdb entry to age")
        aging_interval_buffer = 10
        time.sleep(timeout + aging_interval_buffer)

    if get_platform() in ['cisco', 'clx','ctc']:
        def get_all_bridge_ports(self, bridge_id):
            """
            Loads default 1q bridge ports.

            /* Get bridge ports in default 1Q bridge
                * By default, there will be (m_portCount + m_systemPortCount) number of SAI_BRIDGE_PORT_TYPE_PORT
                * ports and one SAI_BRIDGE_PORT_TYPE_1Q_ROUTER port. The former type of
                * ports will be removed. */
            vector<sai_object_id_t> bridge_port_list(m_portCount + m_systemPortCount + 1);
            """
            print("Get bridge ports...")

            bridge_size = self.system_port_no + self.active_ports_no + 1
            attr = sai_thrift_get_bridge_attribute(
                        self.client,
                        bridge_oid=bridge_id,
                        port_list=sai_thrift_object_list_t(
                            idlist=[], count=bridge_size))
            default_1q_bridge_port_list = attr['port_list'].idlist
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
            return default_1q_bridge_port_list

        def remove_all_bridge_ports(self):
            """
            Remove bridge ports (bridge will not be removed).

            """
            print("Remove all bridge ports...")
            bp_ports = self.def_bridge_port_list
            removed_list = []
            for index, port in enumerate(bp_ports):
                sai_thrift_remove_bridge_port(self.client, port)
                removed_list.append(port)
            for bridge_id in removed_list:
                self.def_bridge_port_list.remove(bridge_id)
            print("Removed bridge {}, left {}".format(len(removed_list), len(bp_ports)))
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

        def remove_bridge_ports(self):
            """
            Remove default bridge ports
            """

            for bridge_port in self.def_bridge_port_list:
                sai_thrift_remove_bridge_port(self.client, bridge_port)

def hexstr_to_ascii(h):
    list_s = []
    for i in range(0, len(h), 2):
        list_s.append(chr(int(h[i:i+2],16)))
    return ''.join(list_s)

def simple_eth_packet(pktlen=60,
                       eth_dst='00:01:02:03:04:05',
                       eth_src='00:06:07:08:09:0a',
                       dl_vlan_enable=False,
                       vlan_vid=0,
                       vlan_pcp=0,
                       dl_vlan_cfi=0,
                       eth_type=0x88cc,
                       inner_frame = None):

     if MINSIZE > pktlen:
         pktlen = MINSIZE

     if (dl_vlan_enable):
         pkt = packet.Ether(dst=eth_dst, src=eth_src)/ \
             packet.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid, type=eth_type)
     else:
         pkt = packet.Ether(dst=eth_dst, src=eth_src, type=eth_type)

     if inner_frame:
         pkt = pkt / inner_frame.encode('latin1')


     payload = hexstr_to_ascii('00' * (pktlen - len(pkt)))
     pkt = pkt/ payload

     return pkt


def simple_udp_packet(
    pktlen=100,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    dl_vlan_cfi=0,
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    udp_sport=1234,
    udp_dport=80,
    ip_ihl=None,
    ip_options=False,
    ip_flag=0,
    ip_id=1,
    with_udp_chksum=True,
    udp_payload=None,
    pattern_type=None
):
    """
    Return a simple dataplane UDP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param udp_dport UDP destination port
    @param udp_sport UDP source port
    @param with_udp_chksum Valid UDP checksum

    Generates a simple UDP packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/UDP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_udp_chksum:
        udp_hdr = packet.UDP(sport=udp_sport, dport=udp_dport)
    else:
        udp_hdr = packet.UDP(sport=udp_sport, dport=udp_dport, chksum=0)

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if dl_vlan_enable:
        pkt = (
            packet.Ether(dst=eth_dst, src=eth_src)
            / packet.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)
            / packet.IP(
                src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, id=ip_id
            )
            / udp_hdr
        )
    else:
        if not ip_options:
            pkt = (
                packet.Ether(dst=eth_dst, src=eth_src)
                / packet.IP(
                    src=ip_src,
                    dst=ip_dst,
                    tos=ip_tos,
                    ttl=ip_ttl,
                    ihl=ip_ihl,
                    id=ip_id,
                    flags=ip_flag,
                )
                / udp_hdr
            )
        else:
            pkt = (
                packet.Ether(dst=eth_dst, src=eth_src)
                / packet.IP(
                    src=ip_src,
                    dst=ip_dst,
                    tos=ip_tos,
                    ttl=ip_ttl,
                    ihl=ip_ihl,
                    options=ip_options,
                    id=ip_id,
                    flags=ip_flag,
                )
                / udp_hdr
            )

    if udp_payload:
        pkt = pkt / udp_payload.encode('latin1')
    if pattern_type == None:
        pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pktlen - len(pkt))]), "hex")
    else:
        pkt = pkt/(chr(0) * (pktlen - len(pkt)))

    return pkt


class SaiHelperUtilsMixin:
    """
    Mixin utils class providing API for convenient SAI objects creation/deletion
    """

    def create_bridge_ports(self, ports=None):
        """
        Create bridge ports base on port_list.
        """
        ports = ports or range(0, len(self.port_list))
        for port_index in ports:
            port_id = getattr(self, 'port%s' % port_index)
            port_bp = sai_thrift_create_bridge_port(
                self.client,
                bridge_id=self.default_1q_bridge,
                port_id=port_id,
                type=SAI_BRIDGE_PORT_TYPE_PORT,
                admin_state=True)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
            setattr(self, 'port%s_bp' % port_index, port_bp)
            self.def_bridge_port_list.append(port_bp)

    def destroy_bridge_ports(self):
        for bridge_port in self.def_bridge_port_list:
            sai_thrift_remove_bridge_port(self.client, bridge_port)

    def create_lag_with_members(self, lag_index, ports):
        # create lag
        lag_id = sai_thrift_create_lag(self.client)
        setattr(self, 'lag%s' % lag_index, lag_id)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
        self.def_lag_list.append(lag_id)

        # add LAG to bridge
        lag_bp = sai_thrift_create_bridge_port(
            self.client,
            bridge_id=self.default_1q_bridge,
            port_id=lag_id,
            type=SAI_BRIDGE_PORT_TYPE_PORT,
            admin_state=True)

        setattr(self, 'lag%s_bp' % lag_index, lag_bp)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
        self.def_bridge_port_list.append(lag_bp)

        # add lag members
        for member_index in ports:
            port_id = getattr(self, 'port%s' % member_index)
            lag_member = sai_thrift_create_lag_member(
                self.client, lag_id=lag_id, port_id=port_id)
            setattr(self, "lag%s_member%s" % (lag_index, member_index), lag_member)

            self.def_lag_member_list.append(lag_member)

    def destroy_lags_with_members(self):
        for lag_member in self.def_lag_member_list:
            sai_thrift_remove_lag_member(self.client, lag_member)
        for lag in self.def_lag_list:
            sai_thrift_remove_lag(self.client, lag)

    def create_vlan_with_members(self, vlan_index, members):
        # create vlan
        vlan_id = sai_thrift_create_vlan(self.client, vlan_id=vlan_index)
        setattr(self, 'vlan%s' % vlan_index, vlan_id)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
        self.def_vlan_list.append(vlan_id)

        # add members
        idx = 0
        for member, tag in members.items():
            if tag == 'tagged':
                tag = SAI_VLAN_TAGGING_MODE_TAGGED
            else:
                tag = SAI_VLAN_TAGGING_MODE_UNTAGGED
            vlan_member_id = sai_thrift_create_vlan_member(
                self.client,
                vlan_id=vlan_id,
                bridge_port_id=member,
                vlan_tagging_mode=tag)
            setattr(self, 'vlan%s_member%s' % (vlan_index, idx), vlan_member_id)
            self.def_vlan_member_list.append(vlan_member_id)
            idx = idx + 1

    def destroy_vlans_with_members(self):
        for vlan_member in self.def_vlan_member_list:
            sai_thrift_remove_vlan_member(self.client, vlan_member)
        for vlan in self.def_vlan_list:
            sai_thrift_remove_vlan(self.client, vlan)

    def create_routing_interfaces(self, vlans = None, lags = None, ports = None):
        # iterate through vlans
        if vlans is not None:
            for vlan in vlans:
                vlan_id = getattr(self, "vlan%s" % vlan)
                vlan_rif = sai_thrift_create_router_interface(
                    self.client,
                    type=SAI_ROUTER_INTERFACE_TYPE_VLAN,
                    virtual_router_id=self.default_vrf,
                    vlan_id=vlan_id)
                self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
                setattr(self, "vlan%s_rif" % vlan, vlan_rif)
                self.def_rif_list.append(vlan_rif)

        # iterate through lags
        if lags is not None:
            for lag in lags:
                lag_id = getattr(self, "lag%s" % lag)
                lag_rif = sai_thrift_create_router_interface(
                    self.client,
                    type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                    virtual_router_id=self.default_vrf,
                    port_id=lag_id)
                self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
                setattr(self, "lag%s_rif" % lag, lag_rif)
                self.def_rif_list.append(lag_rif)

        # iterate through ports
        if ports is not None:
            for port in ports:
                port_id = getattr(self, 'port%s' % port)
                port_rif = sai_thrift_create_router_interface(
                    self.client,
                    type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                    virtual_router_id=self.default_vrf,
                    port_id=port_id)
                self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
                setattr(self, "port%s_rif" % port, port_rif)
                self.def_rif_list.append(port_rif)

    def destroy_routing_interfaces(self):
        for rif in self.def_rif_list:
            sai_thrift_remove_router_interface(self.client, rif)

    def read_cpu_trap_pkts(self, cpu_queue=None):
        """Counter snapshot for verifying a packet was trapped to CPU.

        BRCM: trap traffic bypasses the user-visible cpu_queue, so read
        the cpu_port UC counter instead (cpu_queue arg is ignored).
        Other platforms read the given cpu_queue (default cpu_queue0).
        """
        if get_platform() == 'brcm':
            return query_counter(
                self, sai_thrift_get_port_stats,
                self.cpu_port_hdl)["SAI_PORT_STAT_IF_IN_UCAST_PKTS"]
        if cpu_queue is None:
            cpu_queue = self.cpu_queue0
        return query_counter(
            self, sai_thrift_get_queue_stats,
            cpu_queue)["SAI_QUEUE_STAT_PACKETS"]

    def assert_cpu_trap_delta(self, pre, post, expected=1):
        """Assert exactly `expected` packets were trapped to CPU."""
        self.assertEqual(post - pre, expected)


class SaiHelperSimplified(SaiHelperUtilsMixin, SaiHelperBase):
    """
    SAI test helper class for DUT with limited port resources
    without initial switch ports setup
    """

    def __getattr__(self, name):
        """
        Skip the test when a requested port attribute does not exist.
        """
        # NOTE: check only ports for now
        found = re.findall(r'^port\d+$', name)
        if found and found[0]:
            self.skipTest(SKIP_TEST_NO_RESOURCES_MSG)

    def setUp(self, skip_reason=None):
        super(SaiHelperSimplified, self).setUp(skip_reason=skip_reason)

        # lists of default objects
        self.def_bridge_port_list = []
        self.def_lag_list = []
        self.def_lag_member_list = []
        self.def_vlan_list = []
        self.def_vlan_member_list = []
        self.def_rif_list = []

    def tearDown(self):
        super(SaiHelperSimplified, self).tearDown()


class SaiHelper(SaiHelperUtilsMixin, SaiHelperBase):
    """
    Set common base ports configuration for tests

    Common ports configuration:
    * U/T = untagged/tagged VLAN member
    +--------+------+-----------+-------------+--------+------------+------------+
    | Port   | LAG  | _member   | Bridge port | VLAN   | _member    | RIF        |
    +========+======|===========+=============+========+============+============+
    | port0  |      |           | port0_bp    | vlan10 | _member0 U |            |
    | port1  |      |           | port1_bp    |        | _member1 T |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port2  |      |           | port2_bp    | vlan20 | _member0 U |            |
    | port3  |      |           | port3_bp    |        | _member1 T |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port4  | lag1 | _member4  | lag1_bp     | vlan10 | _member2 U |            |
    | port5  |      | _member5  |             |        |            |            |
    | port6  |      | _member6  |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port7  | lag2 | _member7  | lag2_bp     | vlan20 | _member2 T |            |
    | port8  |      | _member8  |             |        |            |            |
    | port9  |      | _member9  |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port10 |      |           |             |        |            | port10_rif |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port11 |      |           |             |        |            | port11_rif |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port12 |      |           |             |        |            | port12_rif |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port13 |      |           |             |        |            | port13_rif |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port14 | lag3 | _member14 |             |        |            | lag3_rif   |
    | port15 |      | _member15 |             |        |            |            |
    | port16 |      | _member16 |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port17 | lag4 | _member17 |             |        |            | lag4_rif   |
    | port18 |      | _member18 |             |        |            |            |
    | port19 |      | _member19 |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port20 |      |           | port20_bp   | vlan30 | _member0 U | vlan30_rif |
    | port21 |      |           | port21_bp   |        | _member1 T |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port22 | lag5 | _member22 | lag5_bp     | vlan30 | _member2 T |            |
    | port23 |      | _member23 |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port24 |                                                                   |
    | port25 |                                                                   |
    | port26 |                                                                   |
    | port27 |                            UNASSIGNED                             |
    | port28 |                                                                   |
    | port29 |                                                                   |
    | port30 |                                                                   |
    | port31 |                                                                   |
    +--------+-------------------------------------------------------------------+
    """

    def create_default_v4_v6_route_entry(self):
        """
        Create default v4 and v6 route entry.
        """
        DEFAULT_IP_V4_PREFIX = '0.0.0.0/0'
        DEFAULT_IP_V6_PREFIX = '0000:0000:0000:0000:0000:0000:0000:0000'
        print("Create default v4&v6 route entry...")
        v6_default = sai_thrift_ip_prefix_t(addr_family=1,
                                            addr=sai_thrift_ip_addr_t(
                                                ip6=DEFAULT_IP_V6_PREFIX),
                                            mask=sai_thrift_ip_addr_t(ip6=DEFAULT_IP_V6_PREFIX))
        self.default_ipv6_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                 destination=v6_default)
        status = sai_thrift_create_route_entry(
            self.client,
            route_entry=self.default_ipv6_route_entry,
            packet_action=SAI_PACKET_ACTION_DROP)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        self.default_ipv4_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                 destination=sai_ipprefix(DEFAULT_IP_V4_PREFIX))
        status = sai_thrift_create_route_entry(
            self.client,
            route_entry=self.default_ipv4_route_entry,
            packet_action=SAI_PACKET_ACTION_DROP)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

    def setUp(self, skip_reason = None):
        super().setUp(skip_reason = skip_reason)

        # lists of default objects
        self.def_bridge_port_list = []
        self.def_lag_list = []
        self.def_lag_member_list = []
        self.def_vlan_list = []
        self.def_vlan_member_list = []
        self.def_rif_list = []

        # create bridge ports
        self.create_bridge_ports(ports=[0, 1, 2, 3, 20, 21])

        self.create_lag_with_members(1, ports=[4, 5, 6])
        self.create_lag_with_members(2, ports=[7, 8, 9])

        # L3 lags
        self.create_lag_with_members(3, ports=[14, 15, 16])
        self.create_lag_with_members(4, ports=[17, 18, 19])
        self.create_lag_with_members(5, ports=[22, 23])

        # create vlan 10 with port0, port1 and lag1
        self.create_vlan_with_members(10, {self.port0_bp: 'untagged',
                                           self.port1_bp: 'tagged',
                                           self.lag1_bp: 'untagged'})

        # create vlan 20 with port2, port3 and lag2
        self.create_vlan_with_members(20, {self.port2_bp: 'untagged',
                                           self.port3_bp: 'tagged',
                                           self.lag2_bp: 'tagged'})

        # create vlan 30 with port20, port21 and lag5
        self.create_vlan_with_members(30, {self.port20_bp: 'untagged',
                                           self.port21_bp: 'tagged',
                                           self.lag5_bp: 'tagged'})

        # setup untagged ports
        sai_thrift_set_port_attribute(self.client, self.port0, port_vlan_id=10)
        sai_thrift_set_lag_attribute(self.client, self.lag1, port_vlan_id=10)
        sai_thrift_set_port_attribute(self.client, self.port2, port_vlan_id=20)
        sai_thrift_set_port_attribute(self.client, self.port20, port_vlan_id=30)


        # create L3 configuration
        self.create_routing_interfaces(vlans=[30])
        self.create_routing_interfaces(lags=[3, 4])
        self.create_routing_interfaces(ports=[10, 11, 12, 13])

        # Create default route for default VRF is mandartory.
        # Issue #1606(https://github.com/opencomputeproject/SAI/issues/1606)
        # Creating route in default VRF will failed if there aren't default routes.
        # Solution
        # Create default route before create route in detaul VRF
        self.create_default_v4_v6_route_entry()

        wait_sec = 2
        print("Waiting for switch to get ready before test, {} seconds ...".format(
            wait_sec))
        time.sleep(wait_sec)

    def tearDown(self):
        if get_platform() == 'cisco' or get_platform() == 'ctc' or get_platform() == 'clx':
            self.destroy_default_v4_v6_route_entry()
        sai_thrift_set_port_attribute(self.client, self.port2, port_vlan_id=0)
        sai_thrift_set_lag_attribute(self.client, self.lag1, port_vlan_id=0)
        sai_thrift_set_port_attribute(self.client, self.port0, port_vlan_id=0)

        self.destroy_routing_interfaces()
        self.destroy_vlans_with_members()
        self.destroy_bridge_ports()
        self.destroy_lags_with_members()

        sai_thrift_flush_fdb_entries(self.client, entry_type=SAI_FDB_FLUSH_ENTRY_TYPE_DYNAMIC)
        super(SaiHelper, self).tearDown()

    if get_platform() == 'cisco':
        def destroy_default_v4_v6_route_entry(self):
            DEFAULT_IP_V4_PREFIX = '0.0.0.0/0'
            DEFAULT_IP_V6_PREFIX = '0000:0000:0000:0000:0000:0000:0000:0000/0'
            print("Remove default v4&v6 route entry...")
            v6_default = sai_thrift_ip_prefix_t(addr_family=1,
                                                addr=sai_thrift_ip_addr_t(
                                                    ip6=DEFAULT_IP_V6_PREFIX),
                                                mask=sai_thrift_ip_addr_t(ip6=DEFAULT_IP_V6_PREFIX))
            self.default_ipv6_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                    destination=v6_default)
            status = sai_thrift_remove_route_entry(
                self.client,
                route_entry=self.default_ipv6_route_entry)

            self.default_ipv4_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                    destination=sai_ipprefix(DEFAULT_IP_V4_PREFIX))
            status = sai_thrift_remove_route_entry(
                self.client,
                route_entry=self.default_ipv4_route_entry)
    if get_platform() == 'ctc':
        def destroy_default_v4_v6_route_entry(self):
            DEFAULT_IP_V4_PREFIX = '0.0.0.0/0'
            DEFAULT_IP_V6_PREFIX = '0000:0000:0000:0000:0000:0000:0000:0000'
            print("Remove default v4&v6 route entry...")
            v6_default = sai_thrift_ip_prefix_t(addr_family=1,
                                                addr=sai_thrift_ip_addr_t(
                                                    ip6=DEFAULT_IP_V6_PREFIX),
                                                mask=sai_thrift_ip_addr_t(ip6=DEFAULT_IP_V6_PREFIX))
            self.default_ipv6_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                    destination=v6_default)
            status = sai_thrift_remove_route_entry(
                self.client,
                route_entry=self.default_ipv6_route_entry)

            self.default_ipv4_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                    destination=sai_ipprefix(DEFAULT_IP_V4_PREFIX))
            status = sai_thrift_remove_route_entry(
                self.client,
                route_entry=self.default_ipv4_route_entry)
    if get_platform() == 'clx':
        def destroy_default_v4_v6_route_entry(self):
            DEFAULT_IP_V4_PREFIX = '0.0.0.0/0'
            DEFAULT_IP_V6_PREFIX = '0000:0000:0000:0000:0000:0000:0000:0000'
            print("Remove default v4&v6 route entry...")
            v6_default = sai_thrift_ip_prefix_t(addr_family=1,
                                                addr=sai_thrift_ip_addr_t(
                                                    ip6=DEFAULT_IP_V6_PREFIX),
                                                mask=sai_thrift_ip_addr_t(ip6=DEFAULT_IP_V6_PREFIX))
            self.default_ipv6_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                    destination=v6_default)
            status = sai_thrift_remove_route_entry(
                self.client,
                route_entry=self.default_ipv6_route_entry)

            self.default_ipv4_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                    destination=sai_ipprefix(DEFAULT_IP_V4_PREFIX))
            status = sai_thrift_remove_route_entry(
                self.client,
                route_entry=self.default_ipv4_route_entry)

            self.default_ipv4_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                    destination=sai_ipprefix(DEFAULT_IP_V4_PREFIX))
            status = sai_thrift_remove_route_entry(
                self.client,
                route_entry=self.default_ipv4_route_entry)
class MinimalPortVlanConfig(SaiHelperBase):
    """
    Minimal port and vlan configuration. Create port_num bridge ports and add
    them to VLAN with vlan_id. Configure ports as untagged
    """

    def __init__(self, port_num, vlan_id=100):
        """
        Args:
            port_num (int): Number of ports to configure
            vlan_id (int): ID of VLAN that will be created
        """
        super(MinimalPortVlanConfig, self).__init__()

        self.port_num = port_num
        self.vlan_id = vlan_id

    def setUp(self):
        super(MinimalPortVlanConfig, self).setUp()

        if self.port_num > self.active_ports_no:
            raise ValueError('Number of ports to configure %d is higher '
                             'than number of active ports %d'
                             % (self.port_num, self.active_ports_no))

        self.def_bridge_port_list = []
        self.def_vlan_member_list = []

        # create bridge ports
        for port in self.port_list:
            bp = sai_thrift_create_bridge_port(
                self.client, bridge_id=self.default_1q_bridge,
                port_id=port, type=SAI_BRIDGE_PORT_TYPE_PORT,
                admin_state=True)

            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
            self.def_bridge_port_list.append(bp)

        # create vlan
        self.vlan = sai_thrift_create_vlan(self.client, vlan_id=self.vlan_id)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

        # add ports to vlan
        for bridge_port in self.def_bridge_port_list:
            vm = sai_thrift_create_vlan_member(
                self.client, vlan_id=self.vlan,
                bridge_port_id=bridge_port,
                vlan_tagging_mode=SAI_VLAN_TAGGING_MODE_UNTAGGED)

            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
            self.def_vlan_member_list.append(vm)

        # setup untagged ports
        for port in self.port_list:
            status = sai_thrift_set_port_attribute(
                self.client, port, port_vlan_id=self.vlan_id)

            self.assertEqual(status, SAI_STATUS_SUCCESS)

    def tearDown(self):
        # revert untagged ports configuration
        for port in self.port_list:
            sai_thrift_set_port_attribute(
                self.client, port, port_vlan_id=0)

        # remove ports from vlan
        for vlan_member in self.def_vlan_member_list:
            sai_thrift_remove_vlan_member(self.client, vlan_member)

        # remove vlan
        sai_thrift_remove_vlan(self.client, self.vlan)

        # remove bridge ports
        for bridge_port in self.def_bridge_port_list:
            sai_thrift_remove_bridge_port(self.client, bridge_port)

        super(MinimalPortVlanConfig, self).tearDown()

class SaiHelperScaleL2(SaiHelperUtilsMixin, SaiHelperBase):

    def setUp(self):
        super(SaiHelperScaleL2, self).setUp()

        # lists of default objects
        self.def_bridge_port_list = []
        self.def_vlan_list = []
        self.def_vlan_member_list = []
        self.vlan_port_map_dict = {}

        #create bridge ports
        self.create_bridge_ports(ports=None)

        # create vlan 2 with port2, port3 and lag2

        vlan2_member_list = {}
        vlan_index = 2
        vlan_id = sai_thrift_create_vlan(self.client, vlan_id=vlan_index)
        setattr(self, 'vlan%s' % vlan_index, vlan_id)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
        self.def_vlan_list.append(vlan_id)

        for idx in range(0,len(self.port_list)):
            vlan_member_id = sai_thrift_create_vlan_member(
                self.client,
                vlan_id=vlan_id,
                bridge_port_id= self.def_bridge_port_list[idx],
                vlan_tagging_mode=SAI_VLAN_TAGGING_MODE_UNTAGGED)
            setattr(self, 'vlan%s_member%s' % (2, idx), vlan_member_id)
            self.def_vlan_member_list.append(vlan_member_id)

        # compatible with 32/64 ptf ports config json
        max_ptf_port = len(self.port_list) - 1
        self.create_vlan_with_members(3, {self.port0_bp: 'tagged',
                                          getattr(self, 'port%s_bp' % max_ptf_port): 'tagged'})
        self.vlan_port_map_dict[3]={
                    'dev_port': [0, max_ptf_port],
                    'vlan': 3}

        for vlan_id in range(4,max_ptf_port+4):
            self.create_vlan_with_members(vlan_id, {(getattr(self, 'port%s_bp' % (vlan_id-3))): 'tagged',
                                                    (getattr(self, 'port%s_bp' % (vlan_id-4))): 'tagged'})

            self.vlan_port_map_dict[vlan_id] = {
                    'dev_port': [(vlan_id-3),(vlan_id-4)],
                    'vlan': vlan_id}

        for port in self.port_list:
            sai_thrift_set_port_attribute(self.client, port, port_vlan_id=2)

        sw_attr = sai_thrift_get_switch_attribute(
            self.client, fdb_aging_time=True)
        self.default_wait_time = sw_attr["fdb_aging_time"]
        print("Default aging time is {} sec".format(self.default_wait_time))

        self.age_time = 0
        status = sai_thrift_set_switch_attribute(self.client,
                                                 fdb_aging_time=self.age_time)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        attr = sai_thrift_get_switch_attribute(self.client,
                                                  fdb_aging_time=True)
        self.assertEqual(attr["fdb_aging_time"], self.age_time)
        print("Set aging time to {} sec to disable aging".format(self.age_time))

        wait_sec = 2
        print("Waiting for switch to get ready before test, {} seconds ...".format(
            wait_sec))
        time.sleep(wait_sec)

    def tearDown(self):
        status = sai_thrift_set_switch_attribute(
            self.client, fdb_aging_time=self.default_wait_time)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        for port in self.port_list:
            sai_thrift_set_port_attribute(self.client, port, port_vlan_id=1)

        self.destroy_vlans_with_members()
        self.destroy_bridge_ports()
        super(SaiHelperScaleL2, self).tearDown()

    def _calc_and_report_perf(self, op_type, total_count, total_time, sai_time):
        """Calculate and print performance metrics with consistent formatting.

        Returns:
            (overall_perf, sai_perf): the caller passes the chosen value to
            record_spec. This method records nothing itself.
        """
        overall_perf = total_count / total_time if total_time > 0 else 0.0
        sai_perf = total_count / sai_time if sai_time > 0 else 0.0
        sai_ratio = sai_time / total_time * 100 if total_time > 0 else 0.0

        print(f"   [PASS] Result: {total_count}  {op_type}, time: {total_time:.3f}s")
        print(f"   Overall performance: {overall_perf:.0f} {op_type}/s")
        print(f"   SAI performance: {sai_perf:.0f} {op_type}/s (ratio: {sai_ratio:.1f}%)")

        return overall_perf, sai_perf

    # def generate_src_mac(self, start_mac="00:00:00:00:00:01", step=1, count=None):

    #     src_mac_list = []
    #     if count is None:
    #         count = getattr(self, 'total_fdb', 100)

    #     for i in range(count):
    #         src_mac = start_mac + str(i % 100000).zfill(2)
    #         src_mac_list.append(src_mac)

    #     end_addr = start_mac + str ((count - 1) * step).zfill(2)

    #     print(f"Generated {len(src_mac_list)}  (range: {start_mac} - {end_addr})")
    #     return src_mac_list

    def get_available_fdb_entry(self):

        available_fdb_count = sai_thrift_get_switch_attribute(
            self.client, available_fdb_entry=True)['available_fdb_entry']

        return available_fdb_count

    def configure_bum_behavior(self):
        """Set unicast/multicast/broadcast FDB-miss packet action to DROP.

        Optional SAI capability: NOT_SUPPORTED is downgraded to a warning (via
        ignore_api_errors + explicit status check) so it never fails the test.
        """
        bum_actions = [
            ("unicast", "fdb_unicast_miss_packet_action"),
            ("multicast", "fdb_multicast_miss_packet_action"),
            ("broadcast", "fdb_broadcast_miss_packet_action"),
        ]
        ignore_api_errors()
        try:
            for name, attr in bum_actions:
                print(f"Setting {name} FDB miss packet action to drop")
                sai_thrift_set_switch_attribute(
                    self.client, **{attr: SAI_PACKET_ACTION_DROP})
                status = self.status()
                if status == SAI_STATUS_NOT_SUPPORTED:
                    print(f"[WARNING] {attr} not supported on this platform "
                          f"(SAI_STATUS_NOT_SUPPORTED); skipping BUM-drop "
                          f"config for {name} miss (capability absent, test "
                          f"continues)")
                    continue
                if status != SAI_STATUS_SUCCESS:
                    print(f"[WARNING] set {attr} returned status {status}; "
                          f"continuing without BUM-drop for {name} miss")
                    continue

                # Read-back to confirm; the read may itself be unsupported on
                # some chips -- treat as a warning (the set was accepted).
                sw_attr = sai_thrift_get_switch_attribute(
                    self.client, **{attr: True})
                rstatus = self.status()
                if rstatus == SAI_STATUS_NOT_SUPPORTED:
                    print(f"[WARNING] read-back of {attr} not supported "
                          f"(SAI_STATUS_NOT_SUPPORTED); set was accepted, "
                          f"continuing")
                    continue
                if not sw_attr or sw_attr.get(attr) != SAI_PACKET_ACTION_DROP:
                    print(f"[WARNING] {attr} read-back != DROP "
                          f"(got {sw_attr.get(attr) if sw_attr else None}); "
                          f"continuing")
        finally:
            restore_api_error_code()




from platform_helper.common_sai_helper import * # pylint: disable=wildcard-import; lgtm[py/polluting-import]
from platform_helper.bfn_sai_helper import * # pylint: disable=wildcard-import; lgtm[py/polluting-import]
from platform_helper.brcm_sai_helper import * # pylint: disable=wildcard-import; lgtm[py/polluting-import]
from platform_helper.mlnx_sai_helper import * # pylint: disable=wildcard-import; lgtm[py/polluting-import]
from platform_helper.cisco_sai_helper import * # pylint: disable=wildcard-import; lgtm[py/polluting-import]
from platform_helper.clx_sai_helper import * # pylint: disable=wildcard-import; lgtm[py/polluting-import]
from platform_helper.ctc_sai_helper import * # pylint: disable=wildcard-import; lgtm[py/polluting-import]

class PlatformSaiHelper(SaiHelper):
    """
    Class uses to extend from SaiHelper, base on the [platform] class attribute,
    dynamic select a subclass from the platform_helper.
    """
    def __new__(cls, *args, **kwargs):
        sai_helper_subclass_map = {subclass.platform: subclass for subclass in SaiHelper.__subclasses__()}
        common_sai_helper_subclass_map = {subclass.platform: subclass for subclass in CommonSaiHelper.__subclasses__()}
        pl = get_platform()

        if pl in common_sai_helper_subclass_map:
            target_base_class = common_sai_helper_subclass_map[pl]
        else:
            target_base_class = sai_helper_subclass_map[pl]

        cur_cls = cls
        while cur_cls.__base__ != PlatformSaiHelper:
            cur_cls = cur_cls.__base__

        cur_cls.__bases__ = (target_base_class,)

        instance = target_base_class.__new__(cls, *args, **kwargs)
        return instance

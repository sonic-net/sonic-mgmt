"""SAI thrift-based buffer threshold probing tests for SONiC.

This module contains probe-based tests for buffer threshold detection, including:
- testQosPfcXoffProbe: PFC XOFF threshold probing
- testQosIngressDropProbe: Ingress drop threshold probing
- testQosEgressDropProbe: Egress drop threshold probing (lossy queue)
- testQosHeadroomPoolProbe: Headroom pool threshold probing

These tests use advanced probing algorithms to automatically detect buffer thresholds.

CI: probe-tests stage in .azure-pipelines/probe-tests/ triggers UT/IT for changes here.

Parameters:
    --enable_qos_ptf_pdb (bool): Enable pdb debugger in PTF tests. Default is False.
"""

import logging
import pytest
from collections import defaultdict

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, conn_graph_facts    # noqa: F401
from tests.common.fixtures.duthost_utils import dut_qos_maps                             # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                     # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory                     # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                        # noqa: F401
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file                            # noqa: F401
from tests.common.fixtures.ptfhost_utils import iptables_drop_ipv6_tx                       # noqa: F401
from tests.common.dualtor.dual_tor_utils import dualtor_ports                             # noqa: F401
from .qos_sai_base import QosSaiBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


class TestQosProbe(QosSaiBase):
    """TestQosProbe contains probe-based buffer threshold detection tests.

    These tests use advanced algorithms to automatically detect buffer thresholds:
    - Binary search for PFC XOFF threshold
    - Ingress drop threshold detection
    - Egress drop threshold detection (lossy queue)
    - Headroom pool size probing
    """

    @staticmethod
    def find_cell_size(config_dict):
        """Recursively find cell_size in config dictionary."""
        if isinstance(config_dict, dict):
            if 'cell_size' in config_dict:
                return config_dict['cell_size']
            for value in config_dict.values():
                result = TestQosProbe.find_cell_size(value)
                if result is not None:
                    return result
        return None

    # --- Platform Probe Parameter Resolver ---
    # Each platform subclass resolves probe parameters (packet_length, thresholds, etc.)
    # from QoS config. PTF receives resolved params via testParams; no platform checks in PTF.
    # To add a new platform: create a subclass of ProbeParamsResolver and register
    # in _PROBE_RESOLVER_REGISTRY.
    _DEFAULT_CELL_SIZE = 384  # Conservative fallback when cell_size is not in QoS config

    class ProbeParamsResolver:
        """Default resolver: 64B packets, 1 cell per packet.

        Subclasses override __init__ to resolve platform-specific values
        from qosConfig_profile and dutQosConfig.
        """
        packet_length = 64          # class-level default
        cells_per_packet = 1        # class-level default

        def __init__(self, qosConfig_profile=None, dutQosConfig=None):
            pass  # defaults provided by class attributes above

        def resolve_threshold(self, value):
            """Convert a qos.yml threshold to probe-comparable units.

            Returns the value in the same units as probe traffic counting,
            so probe result can be directly compared with expected threshold.

            Default: qos.yml stores thresholds in cell units → divide by cells_per_packet.
            Subclasses override when qos.yml uses different units.
            """
            return value // self.cells_per_packet

    class CiscoProbeParamsResolver(ProbeParamsResolver):
        """Cisco-8000: resolve probe params from QoS config.

        Cisco qos.yml threshold unit convention varies by profile:

        Profiles WITHOUT cell_size (threshold in packet units, divisor=1):
          - xoff_1/xoff_2: pkts_num_trig_pfc, pkts_num_trig_ingr_drp

        Profiles WITH cell_size (threshold in cell units, divisor=cells_per_packet):
          - lossy_queue_1: pkts_num_trig_egr_drp

        This matches legacy sai_qos_tests.py behavior where cell_size presence
        in test_params controls whether // cell_occupancy is applied.

        Note on threshold_divisor vs cells_per_packet asymmetry:
          When cell_size is absent, threshold_divisor=1 (thresholds already in
          packet units) but cells_per_packet may be >1 (e.g. 4 for 1350B/384B).
          cells_per_packet is still needed for pool_size byte-to-packet
          conversion; threshold_divisor controls only resolve_threshold().
        """
        def __init__(self, qosConfig_profile=None, dutQosConfig=None):
            super().__init__()
            qosConfig_profile = qosConfig_profile or {}
            dutQosConfig = dutQosConfig or {}
            self.packet_length = qosConfig_profile.get("packet_size", 64)  # Intentional override

            cell_size = qosConfig_profile.get("cell_size")
            if cell_size is not None:
                # Profile provides cell_size → threshold is in cell units
                self.threshold_divisor = (self.packet_length + cell_size - 1) // cell_size
            else:
                # Profile omits cell_size → threshold is already in packet units
                cell_size = (dutQosConfig.get("param", {}).get("cell_size")
                             or TestQosProbe.find_cell_size(dutQosConfig.get("param", {}))
                             or TestQosProbe._DEFAULT_CELL_SIZE)
                self.threshold_divisor = 1

            self.cells_per_packet = (self.packet_length + cell_size - 1) // cell_size  # Intentional override

        def resolve_threshold(self, value):
            """Convert threshold to probe-comparable units using threshold_divisor."""
            return value // self.threshold_divisor

    # Registry: platform_asic -> ProbeParamsResolver subclass.
    # Keys must match duthost.facts["platform_asic"] values exactly
    # (e.g. "cisco-8000" from Cisco 8000 series devices).
    # Unregistered platforms fall back to the default ProbeParamsResolver.
    _PROBE_RESOLVER_REGISTRY = {
        "cisco-8000": CiscoProbeParamsResolver,
    }

    # Threshold keys in qos.yml that need resolve_threshold conversion
    _THRESHOLD_KEYS = (
        "pkts_num_trig_pfc", "pkts_num_trig_ingr_drp",
        "pkts_num_trig_egr_drp", "pkts_num_trig_pfc_shp",
    )

    @staticmethod
    def get_probe_params(platform_asic, qosConfig_profile, dutQosConfig):
        """Return probe-related testParams dict for PTF.

        Resolves platform-specific ProbeParamsResolver via registry, then
        returns a dict with probe_packet_length, probe_cells_per_packet,
        and thresholds converted to packet units.

        qosConfig_profile may be a non-dict (e.g. hdrm_pool_size can be an
        integer on some platforms); guard to avoid AttributeError/TypeError.

        Usage: testParams.update(self.get_probe_params(...))
        """
        if not isinstance(qosConfig_profile, dict):
            qosConfig_profile = {}
        resolver_cls = TestQosProbe._PROBE_RESOLVER_REGISTRY.get(
            platform_asic, TestQosProbe.ProbeParamsResolver)
        resolver = resolver_cls(qosConfig_profile, dutQosConfig)
        params = {
            "probe_packet_length": resolver.packet_length,
            "probe_cells_per_packet": resolver.cells_per_packet,
        }
        for key in TestQosProbe._THRESHOLD_KEYS:
            if key in qosConfig_profile:
                params[key] = resolver.resolve_threshold(qosConfig_profile[key])
        return params

    @staticmethod
    def get_ingress_drop_counter_mode(dutTestParams):
        """Determine ingress drop counter mode based on platform capability.

        3-level fallback: pg_drop > port_buffer_drop > port_drop
        Currently only cisco-8000 is verified to support pg_drop and port_buffer_drop.
        Broadcom/Mellanox default to port_drop until verified.
        Tracked by: https://github.com/sonic-net/sonic-mgmt/issues/24738
        """
        platform_asic = dutTestParams["basicParams"].get("platform_asic", None)
        if platform_asic == "cisco-8000":
            return "pg_drop"
        return "port_drop"

    @pytest.fixture(scope="class", autouse=True)
    def setup(self, disable_voq_watchdog_class_scope):
        return

    @pytest.mark.parametrize("xoffProfile", ["xoff_1", "xoff_2", "xoff_3", "xoff_4"])
    def testQosPfcXoffProbe(
        self, xoffProfile, duthost, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile, egressLosslessProfile, change_lag_lacp_timer, tbinfo, request
    ):
        # NOTE: this test will be skipped for t2 cisco 8800 if it's not xoff_1 or xoff_2
        """
            Test QoS XOFF limits using PFC XOFF probing algorithm

            Args:
                xoffProfile (pytest parameter): XOFF profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of ingress lossless buffer profile attributes
                egressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes
                set_static_route (Fixture): Setup the static route if the src
                                            and dst ASICs are different.

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        normal_profile = ["xoff_1", "xoff_2"]
        if not dutConfig["dualTor"] and xoffProfile not in normal_profile:
            pytest.skip(
                "Additional DSCPs are not supported on non-dual ToR ports")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
        else:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        probing_port_ids = [dutConfig["testPorts"]["src_port_id"], dutConfig["testPorts"]["dst_port_id"]]
        logger.info(f"Simplified probing strategy: using "
                    f"src_port_id={dutConfig['testPorts']['src_port_id']}, "
                    f"dst_port_id={dutConfig['testPorts']['dst_port_id']}")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
        testParams.update({"test_port_ips": dutConfig["testPortIps"]})
        testParams.update({"probing_port_ids": probing_port_ids})
        testParams.update({
            "dscp": qosConfig[xoffProfile]["dscp"],
            "ecn": qosConfig[xoffProfile]["ecn"],
            "pg": qosConfig[xoffProfile]["pg"],
            "buffer_max_size": ingressLosslessProfile["size"],
            "queue_max_size": egressLosslessProfile["static_th"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig[xoffProfile]["pkts_num_trig_pfc"],
            "pkts_num_trig_ingr_drp": qosConfig[xoffProfile]["pkts_num_trig_ingr_drp"],
            "hwsku": dutTestParams['hwsku'],
            "src_dst_asic_diff": (dutConfig['dutAsic'] != dutConfig['dstDutAsic'])
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if dutTestParams["basicParams"].get("platform_asic", None) == "cisco-8000" \
                and not get_src_dst_asic_and_duts["src_long_link"] and get_src_dst_asic_and_duts["dst_long_link"]:
            if "pkts_num_egr_mem_short_long" in list(qosConfig.keys()):
                testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem_short_long"]
            else:
                pytest.skip(
                    "pkts_num_egr_mem_short_long is missing in yaml file ")

        if "pkts_num_margin" in list(qosConfig[xoffProfile].keys()):
            testParams["pkts_num_margin"] = qosConfig[xoffProfile]["pkts_num_margin"]

        if "packet_size" in list(qosConfig[xoffProfile].keys()):
            testParams["packet_size"] = qosConfig[xoffProfile]["packet_size"]

        if 'cell_size' in list(qosConfig[xoffProfile].keys()):
            testParams["cell_size"] = qosConfig[xoffProfile]["cell_size"]

        bufferConfig = dutQosConfig["bufferConfig"]
        testParams["ingress_lossless_pool_size"] = bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["size"]
        testParams["egress_lossy_pool_size"] = bufferConfig["BUFFER_POOL"].get(
            "egress_lossy_pool", {"size": "0"})["size"]

        # Get cell_size with fallback to sub-layers if not found at top level
        cell_size = dutQosConfig["param"].get("cell_size", None)
        if cell_size is None:
            cell_size = self.find_cell_size(dutQosConfig["param"])
        testParams["cell_size"] = cell_size

        # Get pdb parameter from command line
        enable_qos_ptf_pdb = request.config.getoption("--enable_qos_ptf_pdb", default=False)

        # Platform probe params: packet_length, cells_per_packet, threshold conversions
        platform_asic = dutTestParams["basicParams"].get("platform_asic", None)
        testParams.update(self.get_probe_params(platform_asic, qosConfig[xoffProfile], dutQosConfig))

        self.runPtfTest(
            ptfhost, testCase="pfc_xoff_probing.PfcXoffProbing", testParams=testParams,
            pdb=enable_qos_ptf_pdb, test_subdir='probe'
        )

    @pytest.mark.parametrize("xoffProfile", ["xoff_1", "xoff_2", "xoff_3", "xoff_4"])
    def testQosIngressDropProbe(
        self, xoffProfile, duthost, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile, egressLosslessProfile, change_lag_lacp_timer, tbinfo, request
    ):
        """
            Test QoS Ingress Drop limits using IngressDropProbe

            Args:
                xoffProfile (pytest parameter): XOFF profile (used for config lookup)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of ingress lossless buffer profile attributes
                egressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        normal_profile = ["xoff_1", "xoff_2"]
        if not dutConfig["dualTor"] and xoffProfile not in normal_profile:
            pytest.skip(
                "Additional DSCPs are not supported on non-dual ToR ports")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
        else:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        probing_port_ids = [dutConfig["testPorts"]["src_port_id"], dutConfig["testPorts"]["dst_port_id"]]
        logger.info(f"Simplified probing strategy: using "
                    f"src_port_id={dutConfig['testPorts']['src_port_id']}, "
                    f"dst_port_id={dutConfig['testPorts']['dst_port_id']}")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
        testParams.update({"test_port_ips": dutConfig["testPortIps"]})
        testParams.update({"probing_port_ids": probing_port_ids})
        testParams.update({
            "dscp": qosConfig[xoffProfile]["dscp"],
            "ecn": qosConfig[xoffProfile]["ecn"],
            "pg": qosConfig[xoffProfile]["pg"],
            "buffer_max_size": ingressLosslessProfile["size"],
            "queue_max_size": egressLosslessProfile["static_th"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig[xoffProfile]["pkts_num_trig_pfc"],
            "pkts_num_trig_ingr_drp": qosConfig[xoffProfile]["pkts_num_trig_ingr_drp"],
            "hwsku": dutTestParams['hwsku'],
            "src_dst_asic_diff": (dutConfig['dutAsic'] != dutConfig['dstDutAsic'])
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if dutTestParams["basicParams"].get("platform_asic", None) == "cisco-8000" \
                and not get_src_dst_asic_and_duts["src_long_link"] and get_src_dst_asic_and_duts["dst_long_link"]:
            if "pkts_num_egr_mem_short_long" in list(qosConfig.keys()):
                testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem_short_long"]
            else:
                pytest.skip(
                    "pkts_num_egr_mem_short_long is missing in yaml file ")

        if "pkts_num_margin" in list(qosConfig[xoffProfile].keys()):
            testParams["pkts_num_margin"] = qosConfig[xoffProfile]["pkts_num_margin"]

        if "packet_size" in list(qosConfig[xoffProfile].keys()):
            testParams["packet_size"] = qosConfig[xoffProfile]["packet_size"]

        if 'cell_size' in list(qosConfig[xoffProfile].keys()):
            testParams["cell_size"] = qosConfig[xoffProfile]["cell_size"]

        bufferConfig = dutQosConfig["bufferConfig"]
        testParams["ingress_lossless_pool_size"] = bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["size"]
        testParams["egress_lossy_pool_size"] = bufferConfig["BUFFER_POOL"].get(
            "egress_lossy_pool", {"size": "0"})["size"]

        # Get cell_size with fallback to sub-layers if not found at top level
        cell_size = dutQosConfig["param"].get("cell_size", None)
        if cell_size is None:
            cell_size = self.find_cell_size(dutQosConfig["param"])
        testParams["cell_size"] = cell_size

        # Get pdb parameter from command line
        enable_qos_ptf_pdb = request.config.getoption("--enable_qos_ptf_pdb", default=False)

        testParams["ingress_drop_counter_mode"] = self.get_ingress_drop_counter_mode(dutTestParams)

        # Platform probe params: packet_length, cells_per_packet, threshold conversions
        platform_asic = dutTestParams["basicParams"].get("platform_asic", None)
        testParams.update(self.get_probe_params(platform_asic, qosConfig[xoffProfile], dutQosConfig))

        self.runPtfTest(
            ptfhost, testCase="ingress_drop_probing.IngressDropProbing", testParams=testParams,
            pdb=enable_qos_ptf_pdb, test_subdir='probe'
        )

    @pytest.mark.parametrize("lossyProfile", ["lossy_queue_1"])
    def testQosEgressDropProbe(
        self, lossyProfile, duthost, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile, egressLosslessProfile, change_lag_lacp_timer, tbinfo, request
    ):
        """
            Test QoS Egress Drop limits using EgressDropProbe

            Args:
                lossyProfile (pytest parameter): Lossy queue profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of ingress lossless buffer profile attributes
                egressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
        else:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]

        if lossyProfile not in qosConfig:
            pytest.skip(f"{lossyProfile} is not defined in QoS config")

        platform_asic = dutTestParams["basicParams"].get("platform_asic", None)
        if platform_asic == "broadcom-dnx":
            pytest.skip("Egress drop probing is not supported on broadcom-dnx")

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        src_port_id = dutConfig["testPorts"]["src_port_id"]
        dst_port_id = dutConfig["testPorts"]["dst_port_id"]
        probing_port_ids = [src_port_id, dst_port_id]
        logger.info(f"Egress drop probing: using src_port_id={src_port_id}, dst_port_id={dst_port_id}")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
        testParams.update({"test_port_ips": dutConfig["testPortIps"]})
        testParams.update({"probing_port_ids": probing_port_ids})
        testParams.update({
            "dscp": qosConfig[lossyProfile]["dscp"],
            "ecn": qosConfig[lossyProfile]["ecn"],
            # EgressDrop probes a dst-port egress queue, not a priority group.
            # The qos.yml field is named `pg` (legacy LossyQueueTest naming),
            # but at the test entry layer we rename to `queue` so PTF code reads
            # `self.queue` directly with no internal alias. Sibling probes
            # (PfcXoff/IngressDrop/HeadroomPool) keep `pg` because they really
            # are PG-semantic.
            "queue": qosConfig[lossyProfile]["pg"],
            "dst_port_id": dst_port_id,
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": src_port_id,
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "hwsku": dutTestParams['hwsku'],
            "src_dst_asic_diff": (dutConfig['dutAsic'] != dutConfig['dstDutAsic'])
        })

        # pkts_num_trig_egr_drp is the *expected* threshold used for assertion.
        # If the platform's qos.yml does not define it (e.g., a new platform yet
        # to be characterized), let the probe still run and print the measured
        # value to the log so we can update qos.yml manually. PTF-side
        # `get_expected_threshold` returns None when this attr is absent, and
        # `probing_base.assert_probing_result` skips the assertion in that case.
        # This aligns with probe's core value: discover thresholds, don't gate on them.
        expected_egr_drp = qosConfig[lossyProfile].get("pkts_num_trig_egr_drp")
        if expected_egr_drp is not None:
            testParams["pkts_num_trig_egr_drp"] = expected_egr_drp
        else:
            logger.info(
                f"pkts_num_trig_egr_drp not defined in {lossyProfile} for this "
                f"platform's qos.yml; probe will run and print the measured "
                f"value for manual qos.yml update."
            )

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "packet_size" in list(qosConfig[lossyProfile].keys()):
            testParams["packet_size"] = qosConfig[lossyProfile]["packet_size"]

        if 'cell_size' in list(qosConfig[lossyProfile].keys()):
            testParams["cell_size"] = qosConfig[lossyProfile]["cell_size"]

        bufferConfig = dutQosConfig["bufferConfig"]
        # Resolve egress_lossy_pool_size to a numeric value at the test entry layer
        # so PTF receives an explicit integer (not a string sentinel). When the platform's
        # qos.yml does not define `egress_lossy_pool`, the value is 0; the PTF-side
        # `get_pool_size()` will then RuntimeError with a clear message rather than silently
        # falling back to the wrong pool. See review findings I2 / I4.
        egress_lossy_pool = bufferConfig["BUFFER_POOL"].get("egress_lossy_pool")
        if egress_lossy_pool and "size" in egress_lossy_pool:
            egress_lossy_pool_size = int(egress_lossy_pool["size"])
        else:
            egress_lossy_pool_size = 0
            logger.info(
                "egress_lossy_pool not present in BUFFER_POOL; PTF will RuntimeError "
                "if the test exercises buffer-size-dependent code paths."
            )
        testParams["egress_lossy_pool_size"] = egress_lossy_pool_size

        # Get cell_size with fallback to sub-layers if not found at top level
        cell_size = dutQosConfig["param"].get("cell_size", None)
        if cell_size is None:
            cell_size = self.find_cell_size(dutQosConfig["param"])
        testParams["cell_size"] = cell_size

        # Get pdb parameter from command line
        enable_qos_ptf_pdb = request.config.getoption("--enable_qos_ptf_pdb", default=False)

        # Platform probe params: packet_length, cells_per_packet, threshold conversions
        platform_asic = dutTestParams["basicParams"].get("platform_asic", None)
        testParams.update(self.get_probe_params(platform_asic, qosConfig[lossyProfile], dutQosConfig))

        self.runPtfTest(
            ptfhost, testCase="egress_drop_probing.EgressDropProbing", testParams=testParams,
            pdb=enable_qos_ptf_pdb, test_subdir='probe'
        )

    def testQosHeadroomPoolProbe(
            self, duthosts, get_src_dst_asic_and_duts, ptfhost, dutTestParams,
            dutConfig, dutQosConfig, ingressLosslessProfile, iptables_drop_ipv6_tx,  # noqa: F811
            change_lag_lacp_timer, tbinfo, request):
        # NOTE: cisco-8800 will skip this test since there are no headroom pool
        """
            Test QoS Headroom pool size using advanced probing

            This test uses a multi-source probing strategy to detect headroom pool limits.

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of ingress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        testPortIps = dutConfig["testPortIps"]

        if 'hdrm_pool_size' not in list(qosConfig.keys()):
            pytest.skip("Headroom pool size is not enabled on this DUT")

        # if no enough ports, src_port_ids is empty list, skip the test
        if not qosConfig['hdrm_pool_size'].get('src_port_ids', None):
            pytest.skip("No enough test ports on this DUT")

        # run 4 pgs and 4 dscps test for dualtor and T1 dualtor scenario
        if not dutConfig['dualTor'] and not dutConfig['dualTorScenario']:
            qosConfig['hdrm_pool_size']['pgs'] = qosConfig['hdrm_pool_size']['pgs'][:2]
            qosConfig['hdrm_pool_size']['dscps'] = qosConfig['hdrm_pool_size']['dscps'][:2]

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']

        src_port_vlans = []

        if ('platform_asic' in dutTestParams["basicParams"] and
                dutTestParams["basicParams"]["platform_asic"] == "broadcom-dnx"):
            # for 100G port speed the number of ports required to fill headroom is huge,
            # hence skipping the test with speed 100G or cable length of 2k
            if portSpeedCableLength not in ['400000_120000m']:
                pytest.skip("Insufficient number of ports to fill the headroom")
            # Need to adjust hdrm_pool_size src_port_ids, dst_port_id and pgs_num based on how many source and dst ports
            # present
            src_ports = dutConfig['testPortIds'][src_dut_index][src_asic_index]
            if len(duthosts) == 1:
                if len(src_ports) < 3:
                    pytest.skip("Insufficient number of src ports for testQosHeadroomPoolProbe")
                qosConfig["hdrm_pool_size"]["src_port_ids"] = src_ports[1:3]
                qosConfig["hdrm_pool_size"]["pgs_num"] = 2 * len(qosConfig["hdrm_pool_size"]["src_port_ids"])
            else:
                if len(src_ports) < 5:
                    pytest.skip("Insufficient number of src ports for testQosHeadroomPoolProbe")
                qosConfig["hdrm_pool_size"]["src_port_ids"] = src_ports[1:5]
                qosConfig["hdrm_pool_size"]["pgs_num"] = 2 * len(qosConfig["hdrm_pool_size"]["src_port_ids"])

            if get_src_dst_asic_and_duts['src_asic'] == get_src_dst_asic_and_duts['dst_asic']:
                # Src and dst are the same asics, leave one for dst port and the rest for src ports
                qosConfig["hdrm_pool_size"]["dst_port_id"] = src_ports[0]

            else:
                qosConfig["hdrm_pool_size"]["dst_port_id"] = dutConfig['testPortIds'][dst_dut_index][dst_asic_index][0]

            src_port_vlans = [testPortIps[src_dut_index][src_asic_index][port]['vlan_id']
                              if 'vlan_id' in testPortIps[src_dut_index][src_asic_index][port]
                              else None for port in qosConfig["hdrm_pool_size"]["src_port_ids"]]
        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts, qosConfig["hdrm_pool_size"])

        # begin - collect all available test ports for probing
        duthost = get_src_dst_asic_and_duts['src_dut']
        src_dut = get_src_dst_asic_and_duts['src_dut']
        src_mgFacts = src_dut.get_extended_minigraph_facts(tbinfo)
        sonicport_to_testport = src_mgFacts.get("minigraph_port_indices", {})

        sonicport_to_pc = {}
        for pc_name, pc_info in src_mgFacts['minigraph_portchannels'].items():
            for member in pc_info['members']:
                sonicport_to_pc[member] = pc_name

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        src_testPortIds = dutConfig["testPortIds"][src_dut_index][src_asic_index]

        sonic_asic_type = dutTestParams["basicParams"].get("sonic_asic_type", "")

        if sonic_asic_type == "broadcom":
            # Broadcom: use bcmcmd to map ports to XPEs, select ports from the
            # XPE with the most available test ports (required for multi-XPE ASICs
            # like TH/TH2 where headroom pool is per-XPE)
            bcmport_to_sonicport = {}
            cmd = " | ".join(("bcmcmd 'knetctrl netif show'",
                              "grep Interface",
                              "awk '{print $4 \"=\" $7}'",
                              "awk -F= '{print $4 \" \" $2}'"))
            result = duthost.shell(cmd)['stdout'].strip('"\'"')
            for line in result.split("\n"):
                if line:
                    parts = line.split()
                    if len(parts) == 2:
                        bcmport_to_sonicport[parts[0]] = parts[1]

            xpe_to_bcmports = defaultdict(list)
            cmd = " | ".join(("bcmcmd 'show pmap'",
                              "grep -vE 'drivshell|show pmap|===|pipe'",
                              "awk '{ print $2 \" \" $1}'"))
            result = duthost.shell(cmd)['stdout'].strip('"\'"')
            for line in result.split("\n"):
                if line:
                    parts = line.split()
                    if len(parts) == 2:
                        xpe_to_bcmports[parts[0]].append(parts[1])
            if dutConfig["dutAsic"] in ("td2", "td3"):
                all_ports = []
                for xpe in list(xpe_to_bcmports.keys()):
                    all_ports.extend(xpe_to_bcmports[xpe])
                    if xpe != '0':
                        del xpe_to_bcmports[xpe]
                xpe_to_bcmports['0'] = all_ports

            cmd = " | ".join(("show int des",
                              r"grep -E 'Ethernet[0-9]+\s+up\s+up'",
                              " awk ' { print $1 } '"))
            sonicports_in_upstate = [intf for intf in duthost.shell(cmd)['stdout'].strip('"\'"').split("\n") if intf]

            xpe_to_sonicports_in_upstate = defaultdict(list)
            for xpe, bcmports in xpe_to_bcmports.items():
                for bcmport in bcmports:
                    if bcmport in bcmport_to_sonicport:
                        if bcmport_to_sonicport[bcmport] in sonicports_in_upstate:
                            xpe_to_sonicports_in_upstate[xpe].append(bcmport_to_sonicport[bcmport])

            xpe_to_sonicports_in_testPortIds = defaultdict(list)
            for xpe, ports in xpe_to_sonicports_in_upstate.items():
                for port in ports:
                    if sonicport_to_testport[port] in src_testPortIds:
                        xpe_to_sonicports_in_testPortIds[xpe].append(port)

            xpe_to_unique_sonicports = defaultdict(list)
            for xpe, ports in xpe_to_sonicports_in_testPortIds.items():
                sorted_ports = sorted(ports, key=lambda port: int(port.replace("Ethernet", "")))
                included_pcs = set()
                for port in sorted_ports:
                    pc = sonicport_to_pc.get(port, None)
                    if pc is None or pc not in included_pcs:
                        xpe_to_unique_sonicports[xpe].append(port)
                        if pc:
                            included_pcs.add(pc)

            xpe_to_testports = defaultdict(list)
            for xpe, sonicports in xpe_to_unique_sonicports.items():
                for sonicport in sonicports:
                    if sonicport in sonicport_to_testport:
                        xpe_to_testports[xpe].append(sonicport_to_testport[sonicport])

            if not xpe_to_testports:
                pytest.skip("No available test ports found for probing (empty XPE mapping)")

            max_ports_xpe = max(xpe_to_testports.keys(),
                                key=lambda xpe: len(xpe_to_testports[xpe]))
            probing_port_ids = xpe_to_testports[max_ports_xpe]
        else:
            # Non-Broadcom (Mellanox, Cisco, etc.): no XPE concept,
            # use all available test ports directly
            probing_port_ids = src_testPortIds

        logger.info(
            f"probing_port_ids {probing_port_ids},\n"
            f"sonic_asic_type {sonic_asic_type},\n"
            f"test_port_ids {dutConfig['testPortIds']},\n"
            f"testPortIps {dutConfig['testPortIps']}"
        )
        # end

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])

        testParams.update({"test_port_ips": dutConfig["testPortIps"]})
        testParams.update({"probing_port_ids": probing_port_ids})

        testParams.update({
            "testbed_type": dutTestParams["topo"],
            "dscps": qosConfig["hdrm_pool_size"]["dscps"],
            "ecn": qosConfig["hdrm_pool_size"]["ecn"],
            "pgs": qosConfig["hdrm_pool_size"]["pgs"],
            "src_port_ids": qosConfig["hdrm_pool_size"]["src_port_ids"],
            "src_port_ips": [testPortIps[src_dut_index][src_asic_index][port]['peer_addr']
                             for port in qosConfig["hdrm_pool_size"]["src_port_ids"]],
            "dst_port_id": qosConfig["hdrm_pool_size"]["dst_port_id"],
            "dst_port_ip":
                testPortIps[dst_dut_index][dst_asic_index][qosConfig["hdrm_pool_size"]["dst_port_id"]]['peer_addr'],
            "pgs_num": qosConfig["hdrm_pool_size"]["pgs_num"],
            "pkts_num_trig_pfc": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_hdrm_full": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_full"],
            "pkts_num_hdrm_partial": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_partial"],
            "hwsku": dutTestParams['hwsku'],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"]
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        pkts_num_trig_pfc_shp = qosConfig["hdrm_pool_size"].get(
            "pkts_num_trig_pfc_shp")
        if pkts_num_trig_pfc_shp:
            testParams["pkts_num_trig_pfc_shp"] = pkts_num_trig_pfc_shp

        packet_size = qosConfig["hdrm_pool_size"].get("packet_size")
        if packet_size:
            testParams["packet_size"] = packet_size
            testParams["cell_size"] = qosConfig["hdrm_pool_size"]["cell_size"]

        margin = qosConfig["hdrm_pool_size"].get("margin")
        if margin:
            testParams["margin"] = margin

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "pkts_num_trig_pfc_multi" in qosConfig["hdrm_pool_size"]:
            testParams.update({"pkts_num_trig_pfc_multi": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc_multi"]})

        bufferConfig = dutQosConfig["bufferConfig"]
        testParams["ingress_lossless_pool_size"] = bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["size"]
        testParams["egress_lossy_pool_size"] = bufferConfig["BUFFER_POOL"].get(
            "egress_lossy_pool", {"size": "0"})["size"]

        # Get cell_size with fallback to sub-layers if not found at top level
        cell_size = dutQosConfig["param"].get("cell_size", None)
        if cell_size is None:
            cell_size = self.find_cell_size(dutQosConfig["param"])
        testParams["cell_size"] = cell_size

        # Get pdb parameter from command line
        enable_qos_ptf_pdb = request.config.getoption("--enable_qos_ptf_pdb", default=False)

        if ('platform_asic' in dutTestParams["basicParams"] and
                dutTestParams["basicParams"]["platform_asic"] == "broadcom-dnx"):
            testParams['src_port_vlan'] = src_port_vlans

        testParams["ingress_drop_counter_mode"] = self.get_ingress_drop_counter_mode(dutTestParams)

        # Platform probe params: packet_length, cells_per_packet, threshold conversions.
        # hdrm_pool_size may lack packet_size/cell_size needed by platform
        # resolvers (e.g. Cisco-8000 defaults to 64B without packet_size).
        # Headroom pool is filled by lossless traffic on the same PGs as xoff,
        # so fall back to xoff_1 profile values when hdrm_pool_size lacks them.
        platform_asic = dutTestParams["basicParams"].get("platform_asic", None)
        hdrm_probe_profile = dict(qosConfig.get("hdrm_pool_size", {}))
        if "packet_size" not in hdrm_probe_profile:
            xoff_fallback = qosConfig.get("xoff_1", {})
            for key in ("packet_size", "cell_size"):
                if key in xoff_fallback and key not in hdrm_probe_profile:
                    hdrm_probe_profile[key] = xoff_fallback[key]
        testParams.update(self.get_probe_params(
            platform_asic, hdrm_probe_profile, dutQosConfig))

        self.runPtfTest(
            ptfhost, testCase="headroom_pool_probing.HeadroomPoolProbing",
            testParams=testParams, pdb=enable_qos_ptf_pdb, test_subdir='probe')

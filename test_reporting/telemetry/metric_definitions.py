"""
This file defines metric labels, metric names, and constant assignments.
"""
from typing import Final
from enum import Enum, unique

# allowed metric labels
METRIC_LABEL_TESTBED: Final[str] = "test.testbed"                    # testbed name/ID
METRIC_LABEL_TEST_BUILD: Final[str] = "test.os.version"              # Software/build version
METRIC_LABEL_TEST_CASE: Final[str] = "test.testcase"                 # test case name/ID
METRIC_LABEL_TEST_FILE: Final[str] = "test.file"                     # test file name
METRIC_LABEL_TEST_JOBID: Final[str] = "test.job.id"                  # test job ID
METRIC_LABEL_DEVICE_ID: Final[str] = "device.id"                     # device refers to the level of switch
METRIC_LABEL_DEVICE_PORT_ID: Final[str] = "device.port.id"
METRIC_LABEL_DEVICE_PSU_ID: Final[str] = "device.psu.id"
METRIC_LABEL_DEVICE_PSU_MODEL: Final[str] = "device.psu.model"
METRIC_LABEL_DEVICE_PSU_SERIAL: Final[str] = "device.psu.serial"
METRIC_LABEL_DEVICE_PSU_HW_REV: Final[str] = "device.psu.hw_rev"     # hardware revision
METRIC_LABEL_DEVICE_QUEUE_ID: Final[str] = "device.queue.id"
METRIC_LABEL_DEVICE_QUEUE_CAST: Final[str] = "device.queue.cast"     # unicast or multicast
METRIC_LABEL_DEVICE_SENSOR_ID: Final[str] = "device.sensor.id"
METRIC_LABEL_DEVICE_PG_ID: Final[str] = "device.pg.id"               # priority group
METRIC_LABEL_DEVICE_BUFFER_POOL_ID: Final[str] = "device.buffer_pool.id"
METRIC_LABEL_DEVICE_INGRESS_PORT_ID: Final[str] = "device.ingress_port.id"
METRIC_LABEL_DEVICE_EGRESS_PORT_ID: Final[str] = "device.egress_port.id"
METRIC_LABEL_DEVICE_TG_TRAFFIC_RATE: Final[str] = "tg.traffic_rate"  # Measured as a percentage of the line rate
METRIC_LABEL_DEVICE_TG_FRAME_BYTES: Final[str] = "tg.frame_bytes"    # Frame size measured in bytes
METRIC_LABEL_DEVICE_TG_RFC2889_ENABLED: Final[str] = "tg.rfc2889.enabled"

# Allowed metric names, grouped into two categories:
# 1) Metrics included in periodic reports
METRIC_NAME_PORT_STATE: Final[str] = "port.state"
METRIC_NAME_PORT_RX_BPS: Final[str] = "port.rx.bps"
METRIC_NAME_PORT_RX_UTIL_PCT: Final[str] = "port.rx.util.pct"   # utilization percentage
METRIC_NAME_PORT_RX_PACKETS_OK: Final[str] = "port.rx.packets.ok"
METRIC_NAME_PORT_RX_PACKETS_ERR: Final[str] = "port.rx.packets.err"
METRIC_NAME_PORT_RX_PACKETS_DROP: Final[str] = "port.rx.packets.drop"
METRIC_NAME_PORT_RX_PACKETS_OVERRUN: Final[str] = "port.rx.packets.overrun"
METRIC_NAME_PORT_TX_BPS: Final[str] = "port.tx.bps"
METRIC_NAME_PORT_TX_UTIL_PCT: Final[str] = "port.tx.util.pct"   # utilization percentage
METRIC_NAME_PORT_TX_PACKETS_OK: Final[str] = "port.tx.packets.ok"
METRIC_NAME_PORT_TX_PACKETS_ERR: Final[str] = "port.tx.packets.err"
METRIC_NAME_PORT_TX_PACKETS_DROP: Final[str] = "port.tx.packets.drop"
METRIC_NAME_PORT_TX_PACKETS_OVERRUN: Final[str] = "port.tx.packets.overrun"

METRIC_NAME_QUEUE_WATERMARK_BYTES: Final[str] = "queue.watermark.bytes"

METRIC_NAME_PSU_VOLTAGE: Final[str] = "psu.voltage"
METRIC_NAME_PSU_CURRENT: Final[str] = "psu.current"
METRIC_NAME_PSU_POWER: Final[str] = "psu.power"
METRIC_NAME_PSU_STATUS: Final[str] = "psu.status"
METRIC_NAME_PSU_LED: Final[str] = "psu.led"

METRIC_NAME_TEMPERATURE_READING: Final[str] = "temperature.reading"
METRIC_NAME_TEMPERATURE_HIGH_TH: Final[str] = "temperature.high_th"
METRIC_NAME_TEMPERATURE_LOW_TH: Final[str] = "temperature.low_th"
METRIC_NAME_TEMPERATURE_CRIT_HIGH_TH: Final[str] = "temperature.crit_high_th"
METRIC_NAME_TEMPERATURE_CRIT_LOW_TH: Final[str] = "temperature.crit_low_th"
METRIC_NAME_TEMPERATURE_WARNING: Final[str] = "temperature.warning"

# 2) Metrics included in final status reports

# Latency are measured nano-seconds
METRIC_NAME_LATENCY_L3_MIN_NS: Final[str] = "latency.l3.min.ns"
METRIC_NAME_LATENCY_L3_MAX_NS: Final[str] = "latency.l3.max.ns"
METRIC_NAME_LATENCY_L3_AVG_NS: Final[str] = "latency.l3.avg.ns"

METRIC_NAME_NO_LOSS_MAX_RATE: Final[str] = "no_loss_max_rate"     # Measured as a percentage of line rate

# convergence time and route recover time are measured in seconds
METRIC_NAME_BGP_CONVERGENCE_TIME_PORT_RESTART: Final[str] = "bgp.convergence_time.port_restart"
METRIC_NAME_BGP_CONVERGENCE_TIME_CONTAINER_RESTART: Final[str] = "bgp.convergence_time.container_restart"
METRIC_NAME_BGP_CONVERGENCE_TIME_NEXTHOP_CHANGE: Final[str] = "bgp.convergence_time.nexthop_change"

METRIC_NAME_ROUTE_RECOVERY_PORT_RESTART: Final[str] = "route.recovery.port_restart"
METRIC_NAME_ROUTE_RECOVERY_CONTAINER_RESTART: Final[str] = "route.recovery.container_restart"
METRIC_NAME_ROUTE_RECOVERY_NEXTHOP_CHANGE: Final[str] = "route.recovery.nexthop_change"

METRIC_NAME_ECN_EGRESS_MARKING: Final[str] = "ecn.egress_marking"
METRIC_NAME_ECN_ACCURACY_MARKING: Final[str] = "ecn.accuracy_marking"

METRIC_NAME_FAILURE_TEST_SINGLE_LINK_DOWN: Final[str] = "failure_test.single_link_down"
METRIC_NAME_FAILURE_TEST_ALL_LINKS_DOWN: Final[str] = "failure_test.all_links_down"
METRIC_NAME_FAILURE_TEST_CONTAINER_CRIPPLE: Final[str] = "failure_test.container_cripple"
METRIC_NAME_FAILURE_TEST_DUT_REBOOT: Final[str] = "failure_test.DUT_reboot"
METRIC_NAME_FAILURE_TEST_NEIGHBOR_REBOOT: Final[str] = "failure_test.neighbor_reboot"
METRIC_NAME_FAILURE_TEST_ROUTE_WITHDRAWAL: Final[str] = "failure_test.route_withdrawal"

METRIC_NAME_FEC_SANITY: Final[str] = "fec.sanity"

METRIC_NAME_PFC_LOSSLESS: Final[str] = "pfc.lossless"
METRIC_NAME_PFC_LOSSY: Final[str] = "pfc.lossy"

METRIC_NAME_QOS_DWRR: Final[str] = "qos.dwrr"

# constant assignments


@unique
class ADMIN_STATUS(Enum):
    DOWN = 0
    UP = 1


@unique
class OPER_STATUS(Enum):
    DOWN = 0
    UP = 1


@unique
class FLAG(Enum):
    ON = 0
    OFF = 1


@unique
class WARNING_STATUS(Enum):
    FALSE = 0
    TRUE = 1


@unique
class FINAL_STATUS(Enum):
    PASS = 0
    FAIL = 1


@unique
class PSU_STATUS(Enum):
    OK = 0
    NOT_OK = 1
    FAILED = 2
    NOT_PRESENT = 3
    OFF_PSU = 4
    UNPOWERED = 5
    UNKNOWN = 6


@unique
class LED_STATE(Enum):
    GREEN = 1
    YELLOW = 2
    RED = 3


@unique
class QUEUE_TYPE(Enum):
    UNICAST = 1
    MULTICAST = 2


@unique
class METRIC_GROUP(Enum):
    PORT_METRICS = "PORT_METRICS"
    PSU_METRICS = "PSU_METRICS"
    QUEUE_METRICS = "QUEUE_METRICS"
    TEMPERATURE_METRICS = "TEMPERATURE_METRICS"
    LATENCY_METRICS = "LATENCY_METRICS"
    NO_LOSS_MAX_RATE_METRICS = "NO_LOSS_MAX_RATE_METRICS"
    BGP_METRICS = "BGP_METRICS"
    ROUTE_METRICS = "ROUTE_METRICS"
    FINAL_STATUS_METRICS = "FINAL_STATUS_METRICS"

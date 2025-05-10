import time
import struct
import socket

from swsscommon import swsscommon


TABLE_PORT_MAPPING = {
    "DASH_VNET_MAPPING_TABLE": 1234, "DASH_ROUTE_TABLE": 1235}


class DefaultResultChecker(object):
    def __init__(self, stats_table, table_name, test_size):
        self.stats_table = stats_table
        self.table_name = table_name
        self.test_size = test_size
        self.previous_count = self.get_count()

    def get_count(self):
        ret = self.stats_table.get(self.table_name)
        if not ret[0]:
            return 0
        return int(dict(ret[1])["SET"])

    def check(self):
        current_count = self.get_count()
        increase_count = current_count - self.previous_count
        return increase_count >= self.test_size


def PerfProducer(table_name, message_generator, checker_class=DefaultResultChecker, test_size=1e6, is_zmq=False):
    test_size = int(test_size)
    assert(test_size > 1)
    appl_db = swsscommon.DBConnector("APPL_DB", 0)
    if is_zmq:
        tbl = swsscommon.ZmqProducerStateTable(
            appl_db,
            table_name,
            "tcp://localhost:{}".format(TABLE_PORT_MAPPING[table_name]))
    else:
        tbl = swsscommon.ProducerStateTable(appl_db, table_name)
    counter_db = swsscommon.DBConnector("COUNTERS_DB", 0)
    orch_stats = swsscommon.Table(counter_db, "ORCH_STATS_TABLE")
    stats_checker = checker_class(orch_stats, table_name, test_size - 1)
    start = time.time()
    for i in range(0, test_size - 1):
        message_generator(tbl, i)
    while not stats_checker.check():
        pass
    # In orchagent, all messages, no matter from Redis or ZMQ, will be dumped to m_toSync.
    # Meanwhile, the counter of orchstats will be increased to the target value after
    # the message has been dumped to m_toSync. We cannot determine messages were really
    # processed by orchagent or just dumped to m_toSync by checking the counter of orchstats.
    # So, we need to wait for a while to make sure all messages have been processed by orchagent
    # by checking the last message as a guard again.
    time.sleep(1)
    message_generator(tbl, test_size)
    stats_checker = checker_class(orch_stats, table_name, 1)
    while not stats_checker.check():
        pass
    end = time.time()
    return test_size / (end - start)


def VnetRouteMessageGenerator(tbl, index):
    ip = socket.inet_ntoa(struct.pack("!L", index))
    key = "F4939FEFC100:{}".format(ip)
    tbl.delete(key)
    value = [("action_type", "vnet"), ("vnet", "Vnet1")]
    tbl.set(key, value)


def VnetPreconfig():
    appl_db = swsscommon.DBConnector("APPL_DB", 0)
    tbl = swsscommon.ProducerStateTable(appl_db, "DASH_APPLIANCE_TABLE")
    tbl.set("1", [("sip", "10.0.0.1"), ("vm_vni", "41")])
    tbl = swsscommon.ProducerStateTable(appl_db, "DASH_VNET_TABLE")
    tbl.set("Vnet1", [("guid", "2b4d57e6-9de4-49b5-80c0-056a36f35110"), ("vni", "451")])
    tbl = swsscommon.ProducerStateTable(appl_db, "DASH_ENI_TABLE")
    tbl.set(
        "F4939FEFC100",
        [
            ("vnet", "Vnet1"),
            ("eni_id", "930cb401-229a-407a-ba9f-5e358418a90e"),
            ("mac_address", "F4:93:9F:EF:C1:00"),
            ("underlay_ip", "125.0.0.1"),
            ("admin_state", "enabled")
        ])
    time.sleep(5)


VnetPreconfig()
perf_ret = PerfProducer("DASH_ROUTE_TABLE", VnetRouteMessageGenerator, test_size=1e6, is_zmq=True)
print(perf_ret)

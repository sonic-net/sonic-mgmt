"""
    Script to query any SAI variable from syncd-rpc-container. The script supports any
    SAI variable that is defined in switch_sai_thrift.sai_headers library. This script
    needs to be run in the PTF container using the commandline:

    Usage:
        ptf --test-dir ixia_saitests/saitests sai_rpc_caller.RPC_Caller\
            --platform-dir ixia_ptftests/ptftests/\
            --platform remote\
            -t 'dutport=44;port_map="0@0";server="1.72.33.5";\
                sai_values=["SAI_QUEUE_STAT_PACKETS","SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"];clear_only=False'

    To clear all sai counters:
        ptf --test-dir ixia_saitests/saitests sai_rpc_caller.RPC_Caller\
            --platform-dir ixia_ptftests/ptftests/\
            --platform remote\
            -t 'dutport=44;port_map="0@0";server="1.72.33.5";sai_values=[];clear_only=True'
"""
import sai_base_test
from switch import switch_init, sai_thrift_clear_all_counters
from switch_sai_thrift.sai_headers import SAI_PORT_ATTR_QOS_QUEUE_LIST
import ptf.testutils as testutils


class RPC_Caller(sai_base_test.ThriftInterfaceDataPlane):
    """

    To check for the queue ECN marked packets counts.
    port's OID and tc_class are required.

    port: port's OID value
    tc_class : 0-7 TC class value
    sai_values : The actual sai values to query for.
    """

    def runTest(self):
        self.test_params = testutils.test_params_get()
        # Parse input parameters
        port = "Ethernet" + str(self.test_params['dutport'])
        stats = self.test_params['sai_values']

        clear_only = self.test_params['clear_only']
        switch_init(self.client)
        if clear_only:
            sai_thrift_clear_all_counters(self.client)
            return

        numeric_stats = []
        for stat in stats:
            numeric_stats.append(globals()[stat])

        port_oid = self.client.sai_thrift_get_port_id_by_front_port(port)
        attrs = self.client.sai_thrift_get_port_attribute(port_oid)
        queue_stats = [x.value for x in attrs.attr_list if x.id ==
                       SAI_PORT_ATTR_QOS_QUEUE_LIST]
        queue_ids = queue_stats[0].objlist.object_id_list

        thrift_results = []
        queue_counters_results = []

        queue_counters_results = []
        tc_count = 0
        for queue in queue_ids:
            if tc_count <= 7:
                thrift_results = self.client.sai_thrift_get_queue_stats(
                    queue, numeric_stats, len(numeric_stats))
                queue_counters_results.append(thrift_results)
                tc_count += 1

        print(queue_counters_results)
        return (queue_counters_results)

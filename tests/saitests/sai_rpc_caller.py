"""
SONiC Dataplane Qos tests
"""
import time
import logging
import sai_base_test
import sys
from switch import *
#from switch_sai_thrift.sai_headers import SAI_QUEUE_STAT_PACKETS, SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS, SAI_QUEUE_STAT_WATERMARK_BYTES, SAI_QUEUE_STAT_DELAY_WATERMARK
from switch_sai_thrift.sai_headers import *
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
        queue_stats = [x.value  for x in attrs.attr_list if x.id == SAI_PORT_ATTR_QOS_QUEUE_LIST]
        queue_ids = queue_stats[0].objlist.object_id_list

        thrift_results=[]
        queue_counters_results=[]

        cnt_ids=[]
        cnt_ids.append(SAI_QUEUE_STAT_PACKETS)
        cnt_ids.append(SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS)
        queue_counters_results = []
        tc_count = 0
        for queue in queue_ids:
            if tc_count <= 7:
                thrift_results = self.client.sai_thrift_get_queue_stats(queue,cnt_ids,len(cnt_ids))
                queue_counters_results.append(thrift_results[1])
                tc_count += 1

        print (queue_counters_results)
        return (queue_counters_results)

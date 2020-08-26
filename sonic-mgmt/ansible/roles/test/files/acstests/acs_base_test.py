"""
Base classes for test cases

Tests will usually inherit from one of these classes to have the controller
and/or dataplane automatically set up.
"""

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils

################################################################
#
# Thrift interface base tests
#
################################################################

class ACSDataplaneTest(BaseTest):

    def setUp(self):
        BaseTest.setUp(self)

        self.test_params = testutils.test_params_get()
        print "You specified the following test-params when invoking ptf:"
        print self.test_params

        # shows how to use a filter on all our tests
        testutils.add_filter(testutils.not_ipv6_filter)

        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        testutils.reset_filters()
        BaseTest.tearDown(self)

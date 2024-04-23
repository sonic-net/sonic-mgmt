package gnmi_long_stress_test

import (
	"testing"

	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins-ondatra/ondatra/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins-ondatra/ondatra/pinstesthelper/pinstesthelper"
	gst "github.com/sonic-net/sonic-mgmt/sdn_tests/pins-ondatra/tests/ondatra/gnmi_stress_helper"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, gpinsbind.New)
}

// gNMI long stress test (8 hour)
func TestGNMILongStressTest(t *testing.T) {
	defer pinstesthelper.NewTearDownOptions(t).WithID("37aea757-8eb4-41a8-87b7-aa26013cfe47").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressTestHelper(t, dut, gst.LongStressTestInterval)
}

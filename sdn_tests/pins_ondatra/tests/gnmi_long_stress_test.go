package gnmi_long_stress_test

import (
	"testing"

	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	gst "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/tests/gnmi_stress_helper"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

// gNMI long stress test (8 hour)
func TestGNMILongStressTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("37aea757-8eb4-41a8-87b7-aa26013cfe47").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressTestHelper(t, dut, gst.LongStressTestInterval)
}

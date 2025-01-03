package installation_test

import (
	"testing"
	"time"

	syspb "github.com/openconfig/gnoi/system"
	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func TestConfigInstallationSuccess(t *testing.T) {
	ttID := "0dedda87-1b76-40a2-8712-24c1572587ee"
	defer testhelper.NewTearDownOptions(t).WithID(ttID).Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	err :=testhelper.ConfigPush(t, dut, nil)
	if err != nil {
		t.Fatalf("switch config push failed due to err : %v", err)
	}
	waitTime, err := testhelper.RebootTimeForDevice(t, dut)
	if err != nil {
		t.Fatalf("Unable to get reboot wait time: %v", err)
	}
	params := testhelper.NewRebootParams().WithWaitTime(waitTime).WithCheckInterval(30*time.Second).WithRequest(syspb.RebootMethod_COLD).WithLatencyMeasurement(ttID, "gNOI Reboot With Type: "+syspb.RebootMethod_COLD.String())
	if err := testhelper.Reboot(t, dut, params); err != nil {
		t.Fatalf("Failed to reboot DUT: %v", err)
	}
}

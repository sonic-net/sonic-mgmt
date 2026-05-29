package port_debug_data_test

import (
	"fmt"
	"testing"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func TestGetPortDebugDataInvalidInterface(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("dba77fa7-b0d1-4412-8136-22dea24ed935").Teardown(t)
	var intfName = "Ethernet99999"
	err := testhelper.HealthzGetPortDebugData(t, ondatra.DUT(t, "DUT"), intfName);
	if err == nil {
		t.Fatalf("Expected RPC failure due to invalid interface %v", intfName)
	}
}

func TestGetPortDebugDataWithTranscevierInserted(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("8f0468c5-6b2c-477c-9cb2-ec099a686268").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	frontPanelPorts, err := testhelper.FrontPanelPortListForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch front panel ports with error %v", err)
	}

	for _, intfName := range frontPanelPorts {
		xcvrName := gnmi.Get(t, dut, gnmi.OC().Interface(intfName).Transceiver().State())
		if gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Empty().State()) {
			// Skip the interfaces without transceiver inserted.
			continue
		}

		t.Logf("Get port debug data from interface %v on xcvr present port %v", intfName, xcvrName)
		err := testhelper.HealthzGetPortDebugData(t, dut, intfName)
		if err != nil {
			t.Fatalf("Expected RPC success, got error %v", err)
		}

	}
}

func TestGetPortDebugDataWithoutTranscevierInserted(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("2229d2e5-1e0b-415b-ac23-b5b05f76e6d4").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	frontPanelPorts, err := testhelper.FrontPanelPortListForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch front panel ports")
	}

	for _, intfName := range frontPanelPorts {
		xcvrName := gnmi.Get(t, dut, gnmi.OC().Interface(intfName).Transceiver().State())
		if !gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Empty().State()) {
			// Skip the interfaces with transceiver inserted.
			fmt.Println(intfName + " : " + xcvrName)
			continue
		}

		t.Logf("Get port debug data from interface %v on xcvr empty port %v", intfName, xcvrName)
		err := testhelper.HealthzGetPortDebugData(t, dut, intfName)
		if err != nil {
			t.Fatalf("Expected RPC success, got error %v", err)
		}

	}
}

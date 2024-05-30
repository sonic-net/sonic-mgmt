package cpu_interface_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
)

var (
	cpuName                          = "CPU"
	pktsPer            uint64        = 7
	counterUpdateDelay time.Duration = 10000 * time.Millisecond
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

// TestGNMICPUName - Check that the CPU name is the expected value.
func TestGNMICPUName(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("f9c713f4-3b1e-4a08-82ae-8c82746160a4").Teardown(t)

	// Select the dut, or device under test.
	dut := ondatra.DUT(t, "DUT")

	// Read the name via /state.
	stateName := gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).Name().State())

	// Verify the information received from the DUT.
	if stateName != cpuName {
		t.Errorf("CPU state Name is %v, wanted %v", stateName, cpuName)
	}

	// Read the name via /config too.
	configName := gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).Name().Config())

	// Verify the information received from the DUT.
	if configName != cpuName {
		t.Errorf("CPU config Name is %v, wanted %v", configName, cpuName)
	}
}

// TestGNMICPUType - Check that the CPU type is 6=ethernetCsmacd.
func TestGNMICPUType(t *testing.T) {
	// Report results in TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("4d8c458f-10cf-45eb-95d6-90911f05134a").Teardown(t)

	// Select the dut, or device under test.
	dut := ondatra.DUT(t, "DUT")

	// Read the type via /state.
	stateType := gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).Type().State())

	// Verify the information received from the DUT.
	if stateType != oc.IETFInterfaces_InterfaceType_ethernetCsmacd {
		t.Errorf("CPU state Type is %v, wanted %v", stateType, oc.IETFInterfaces_InterfaceType_ethernetCsmacd)
	}

	// Read the type via /config.
	configType := gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).Type().Config())

	// Verify the information received from the DUT
	if configType != oc.IETFInterfaces_InterfaceType_ethernetCsmacd {
		t.Errorf("CPU config Type is %v, wanted %v", configType, oc.IETFInterfaces_InterfaceType_ethernetCsmacd)
	}

	// Verify that changing the value via config works, even if we can't
	// set it  other than to IETFInterfaces_InterfaceType_ethernetCsmacd
	gnmi.Replace(t, dut, gnmi.OC().Interface(cpuName).Type().Config(), configType)

	// Read the type via /state again.
	stateType = gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).Type().State())

	// Verify the information received from the DUT.
	if stateType != oc.IETFInterfaces_InterfaceType_ethernetCsmacd {
		t.Errorf("CPU state Type is %v, wanted %v", stateType, oc.IETFInterfaces_InterfaceType_ethernetCsmacd)
	}
}

// TestGNMICPURole - Check the CPU interface role
// - management should be false
// - CPU should be true
func TestGNMICPURole(t *testing.T) {
	// Reports results in TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("202484be-ff32-4aa2-b459-da1a586b1476").Teardown(t)

	// Select the dut, or device under test.
	dut := ondatra.DUT(t, "DUT")

	// Read management via /state.  Note that the config path for
	// these doesn't exist since they're read-only.
	stateMgmt := gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).Management().State())

	// Verify the information received from the DUT
	if stateMgmt != false {
		t.Errorf("CPU state Management is %v, wanted false", stateMgmt)
	}

	// Read the CPU via /state.
	stateCPU := gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).Cpu().State())

	// Verify the information received from the DUT.
	if stateCPU != true {
		t.Errorf("CPU state CPU is %v, wanted true", stateCPU)
	}
}

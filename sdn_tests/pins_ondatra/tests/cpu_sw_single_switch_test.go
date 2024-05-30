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

// TestGNMICPUParentPaths - Check the CPU parent paths.
func TestGNMICPUParentPaths(t *testing.T) {
	// Reports results in TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("799e156c-0369-4969-b1f2-9c1197603131").Teardown(t)

	// Select the dut, or device under test.
	dut := ondatra.DUT(t, "DUT")

	// Read the counters via /state.  Note that the config path for
	// these doesn't exist since they're read-only.  The type
	// for the return value is "type Interface_Counters struct"
	stateCounters := gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).Counters().State())

	// Verify the information received from the DUT.

	// CarrierTransitions isn't expected on CPU interface.
	if stateCounters.CarrierTransitions != nil && stateCounters.GetCarrierTransitions() != 0 {
		t.Errorf("CPU CarrierTransitions is non-zero: %v", stateCounters.GetCarrierTransitions())
	}

	if stateCounters.InBroadcastPkts == nil {
		t.Error("CPU BroadcastPkts is nil")
	}

	if stateCounters.InDiscards == nil {
		t.Error("CPU InDicards is nil")
	}

	// Errors on the CPU interface would be unexpected
	if stateCounters.InErrors == nil {
		t.Error("CPU InErrors is nil")
	}
	if stateCounters.GetInErrors() != 0 {
		t.Errorf("CPU InErrors is non-zero: %v", stateCounters.GetInErrors())
	}

	// FCS errors aren't possible on the CPU interface.
	if stateCounters.InFcsErrors == nil {
		t.Error("CPU InFcsErrors is nil")
	} else {
		if stateCounters.GetInFcsErrors() != 0 {
			t.Errorf("CPU InFcsErrors is non-zero: %v", stateCounters.GetInFcsErrors())
		}
	}

	if stateCounters.InMulticastPkts == nil {
		t.Error("CPU InMulticastPkts is nil")
	}

	if stateCounters.InOctets == nil {
		t.Error("CPU InOctets is nil")
	}

	if stateCounters.InPkts == nil {
		t.Error("CPU InPkts is nil")
	}

	if stateCounters.InUnicastPkts == nil {
		t.Error("CPU InUnicastPkts is nil")
	}

	if stateCounters.InUnknownProtos == nil {
		t.Error("CPU InUnknownProtos is nil")
	}

	if stateCounters.LastClear == nil {
		t.Error("CPU LastClear is nil")
	}

	if stateCounters.OutBroadcastPkts == nil {
		t.Error("CPU OutBroadcastPkts is nil")
	}

	if stateCounters.OutDiscards == nil {
		t.Error("CPU OutDiscards is nil")
	}

	if stateCounters.OutErrors == nil {
		t.Error("CPU OutErrors is nil")
	}

	if stateCounters.OutMulticastPkts == nil {
		t.Error("CPU OutMulticastPkts is nil")
	}

	if stateCounters.OutOctets == nil {
		t.Error("CPU OutOctets is nil")
	}

	if stateCounters.OutPkts == nil {
		t.Error("CPU OutPkts is nil")
	}

	if stateCounters.OutUnicastPkts == nil {
		t.Error("CPU OutUnicastPkts is nil")
	}

	// Read the parent via /state.  Note that the config path for
	// this doesn't exist since it is read-only. The type
	// for the return value is
	// "type OpenconfigInterfaces_Interfaces_Interface_State struct"
	stateIntf := gnmi.Get(t, dut, gnmi.OC().Interface(cpuName).State())

	// Verify the information received from the DUT.

	// AdminStatus may not be valid for CPU so allow for both 0 (not set)
	// or UP as valid options.
	if stateIntf.AdminStatus != oc.Interface_AdminStatus_UNSET && stateIntf.AdminStatus != oc.Interface_AdminStatus_UP {
		t.Errorf("CPU AdminStatus is unexpected: %v", stateIntf.AdminStatus)
	}

	// Validate that Counters isn't nil.
	if stateIntf.Counters == nil {
		t.Error("CPU Counters is nil")
	}

	// Enabled may not be valid for CPU, allow.
	if stateIntf.Enabled != nil && stateIntf.GetEnabled() != true {
		t.Error("CPU is not enabled")
	}

	// LoopbackMode may not be valid for CPU, allow.
	if lpMode := stateIntf.GetLoopbackMode(); lpMode != oc.Interfaces_LoopbackModeType_UNSET && lpMode != oc.Interfaces_LoopbackModeType_NONE {
		t.Errorf("CPU LoopbackMode is not valid: got: %v, want: %v", lpMode, oc.Interfaces_LoopbackModeType_NONE)
	}

	// MTU may not be valid for CPU, allow.
	if stateIntf.Mtu != nil {
		if stateIntf.GetMtu() < 1514 || stateIntf.GetMtu() > 9216 {
			t.Errorf("CPU MTU is unexpected: %v (expected [1514-9216])", stateIntf.GetMtu())
		}
	}

	// Validate the Name.
	if stateIntf.Name == nil {
		t.Error("CPU Name is nil")
	} else {
		name := stateIntf.GetName()
		if name != cpuName {
			t.Errorf("CPU Name is %v", name)
		}
	}

	// OperStatus may not be valid for CPU, allow nil (unset).
	if stateIntf.OperStatus != oc.Interface_OperStatus_UNSET {
		if stateIntf.OperStatus !=
			oc.Interface_OperStatus_UP {
			t.Errorf("CPU OperStatus is unexpected: %v", stateIntf.OperStatus)
		}

	}

	// Validate the Type.
	if stateIntf.Type != oc.IETFInterfaces_InterfaceType_ethernetCsmacd {
		t.Errorf("CPU Type is unexpected: %v", stateIntf.Type)
	}
}

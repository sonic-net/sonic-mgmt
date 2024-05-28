package inband_sw_interface_test

import (
	"net"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/testt"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
)

var (
	inbandSwIntfName              = "Loopback0"
	interfaceIndex                = uint32(0)
	configuredIPv4Path            = "6.7.8.9"
	configuredIPv4PrefixLength    = uint8(32)
	configuredIPv6Path            = "3000::2"
	configuredIPv6PrefixLength    = uint8(128)
	newConfiguredIPv4Path         = "7.8.9.6"
	newConfiguredIPv4PrefixLength = uint8(32)
	newConfiguredIPv6Path         = "3022::2345"
	newConfiguredIPv6PrefixLength = uint8(128)
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

var calledMockConfigPush = false

func mockConfigPush(t *testing.T) {
	// Performs a mock config push by setting up the loopback0 interface database
	// entries and the IPv4 and IPv6 addresses expected to be configured.
	// TODO: Remove calls to this function once the helper function
	// to perform a default config during setup is available.  See b/188927677.

	if calledMockConfigPush {
		return
	}

	// Create the loopback0 interface.
	t.Logf("Config push for %v", inbandSwIntfName)
	dut := ondatra.DUT(t, "DUT")
	d := &oc.Root{}

	newIface := d.GetOrCreateInterface(inbandSwIntfName)
	newIface.Name = &inbandSwIntfName
	newIface.Type = oc.IETFInterfaces_InterfaceType_softwareLoopback
	gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Config(), newIface)

	iface := d.GetOrCreateInterface(inbandSwIntfName).GetOrCreateSubinterface(interfaceIndex)

	// Seed an IPv4 address for the loopback0 interface.
	t.Logf("Config push for %v/%v", configuredIPv4Path, configuredIPv4PrefixLength)
	newV4 := iface.GetOrCreateIpv4().GetOrCreateAddress(configuredIPv4Path)
	newV4.Ip = &configuredIPv4Path
	newV4.PrefixLength = &configuredIPv4PrefixLength
	gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(configuredIPv4Path).Config(), newV4)

	gnmi.Await(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(configuredIPv4Path).Ip().State(), 5*time.Second, configuredIPv4Path)

	// Seed an IPv6 address for the loopback0 interface.
	t.Logf("Config push for %v/%v", configuredIPv6Path, configuredIPv6PrefixLength)
	newV6 := iface.GetOrCreateIpv6().GetOrCreateAddress(configuredIPv6Path)
	newV6.Ip = &configuredIPv6Path
	newV6.PrefixLength = &configuredIPv6PrefixLength
	gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(configuredIPv6Path).Config(), newV6)

	gnmi.Await(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(configuredIPv6Path).Ip().State(), 5*time.Second, configuredIPv6Path)

	calledMockConfigPush = true
}

// TestGNMIInbandSwIntfName - Check inband sw interface name is expected value.
func TestGNMIInbandSwIntfName(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("c147f71d-cd60-4a14-b168-1e50c3003a1d").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	if stateName := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Name().State()); stateName != inbandSwIntfName {
		t.Errorf("Inband sw interface state Name is %v, wanted %v", stateName, inbandSwIntfName)
	}

	if configName := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Name().Config()); configName != inbandSwIntfName {
		t.Errorf("Inband sw interface config Name is %v, wanted %v", configName, inbandSwIntfName)
	}
}

// TestGNMIInbandSwIntfType - Check inband sw interface type is expected value.
func TestGNMIInbandSwIntfType(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("6b4a4bba-b102-4706-ae11-bfb3b0b35cde").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	if stateType := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Type().State()); stateType != oc.IETFInterfaces_InterfaceType_softwareLoopback {
		t.Errorf("Inband sw interface state Type is %v, wanted %v", stateType, "software loopback")
	}
}

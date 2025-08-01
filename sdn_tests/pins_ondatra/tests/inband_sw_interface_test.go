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
	configuredIPv4Path            = "10.10.40.20"
	configuredIPv4PrefixLength    = uint8(32)
	configuredIPv6Path            = "3000::2"
	configuredIPv6PrefixLength    = uint8(128)
	newConfiguredIPv4Path         = "10.10.50.15"
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

// TestGNMIInbandSwIntfMacAddr - Check inband sw interface MAC address is expected format
// TODO: remove this comment: Currently this test fails due to b/192485691.
func TestGNMIInbandSwIntfMacAddr(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("f43768b1-7347-4c25-9f8a-c4c94d0ec923").Teardown(t)
	t.Skip()

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	stateMacAddress := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Ethernet().MacAddress().State())
	if _, err := net.ParseMAC(stateMacAddress); err != nil {
		t.Errorf("Invalid MAC address format received for interface %v! got:%v", inbandSwIntfName, stateMacAddress)
	}
}

// TestGNMIInbandSwIntfOperStatus - Check inband sw interface Oper-Status is expected value.
// TODO: remove this comment: Currently this test fails due to b/194325182
func TestGNMIInbandSwIntfOperStatus(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("9086dbae-2636-400b-8381-f6ff7e5b0772").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	if operStatus := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).OperStatus().State()); operStatus != oc.Interface_OperStatus_UP {
		t.Errorf("%v OperStatus is %v, wanted UP", inbandSwIntfName, operStatus)
	}
}

// TestGNMIInbandSwIntfSetIPv4Addr -- Set and check IPv4 address on the inband sw interface
func TestGNMIInbandSwIntfSetIPv4Addr(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("e99b7744-c11d-458a-84dd-5da351792d04").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	d := &oc.Root{}
	iface := d.GetOrCreateInterface(inbandSwIntfName).GetOrCreateSubinterface(interfaceIndex)

	// Set IPv4 address for the loopback0 interface.
	newV4 := iface.GetOrCreateIpv4().GetOrCreateAddress(newConfiguredIPv4Path)
	newV4.Ip = &newConfiguredIPv4Path
	newV4.PrefixLength = &newConfiguredIPv4PrefixLength
	gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(newConfiguredIPv4Path).Config(), newV4)

	gnmi.Await(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(newConfiguredIPv4Path).Ip().State(), 5*time.Second, newConfiguredIPv4Path)
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(newConfiguredIPv4Path).PrefixLength().State()); got != newConfiguredIPv4PrefixLength {
		t.Errorf("IP prefix length configure failed! got:%v, want:%v", got, newConfiguredIPv4PrefixLength)
	}
}

// TestGNMIInbandSwIntfSetIPv6Addr -- Set and check IPv6 address on the inband sw interface
func TestGNMIInbandSwIntfSetIPv6Addr(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("8bb6c702-905d-4d08-b40b-ca0917ed4511").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	d := &oc.Root{}
	iface := d.GetOrCreateInterface(inbandSwIntfName).GetOrCreateSubinterface(interfaceIndex)

	// Set IPv6 address for the loopback0 interface.
	newV6 := iface.GetOrCreateIpv6().GetOrCreateAddress(newConfiguredIPv6Path)
	newV6.Ip = &newConfiguredIPv6Path
	newV6.PrefixLength = &newConfiguredIPv6PrefixLength
	gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(newConfiguredIPv6Path).Config(), newV6)

	gnmi.Await(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(newConfiguredIPv6Path).Ip().State(), 5*time.Second, newConfiguredIPv6Path)
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(newConfiguredIPv6Path).PrefixLength().State()); got != newConfiguredIPv6PrefixLength {
		t.Errorf("IPv6 prefix length configure failed! got:%v, want:%v", got, newConfiguredIPv6PrefixLength)
	}
}

// TestGNMIInbandSwIntfSetInvalidIPv4AddrAndPrefixLength -- Set and check IPv4 address with invalid address and prefix length on the inband sw interface
func TestGNMIInbandSwIntfSetInvalidIPv4AddrOrPrefixLength(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("72e632a0-b7fc-47a6-8fb4-906363e995cb").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	d := &oc.Root{}
	iface := d.GetOrCreateInterface(inbandSwIntfName).GetOrCreateSubinterface(interfaceIndex)

	// Set invalid IPv4 address on the loopback0 interface.
	var invalidIPPaths = []string{"255.123.231.69", "0.125.120.136"}
	for _, invalidIPPath := range invalidIPPaths {

		newV4 := iface.GetOrCreateIpv4().GetOrCreateAddress(invalidIPPath)
		newV4.Ip = &invalidIPPath
		newV4.PrefixLength = &newConfiguredIPv4PrefixLength
		testt.ExpectFatal(t, func(t testing.TB) {
			gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(invalidIPPath).Config(), newV4)
		})
	}

	// Verify the IP address not changed.
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(newConfiguredIPv4Path).Ip().State()); got != newConfiguredIPv4Path {
		t.Errorf("Negative testing for IP address configure failed! got:%v, want:%v", got, newConfiguredIPv4Path)
	}

	// Set IPv4 address with invalid prefix length for the loopback0 interface.
	var tryConfiguredIPv4Path = "10.10.60.30"
	var badConfiguredIPv4PrefixLength = uint8(24)
	newV4 := iface.GetOrCreateIpv4().GetOrCreateAddress(tryConfiguredIPv4Path)
	newV4.Ip = &tryConfiguredIPv4Path
	newV4.PrefixLength = &badConfiguredIPv4PrefixLength
	testt.ExpectFatal(t, func(t testing.TB) {
		gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(tryConfiguredIPv4Path).Config(), newV4)
	})

	// Verify the IP address and prefix length are not changed.
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(newConfiguredIPv4Path).Ip().State()); got != newConfiguredIPv4Path {
		t.Errorf("Negative testing for IP address configure failed! got:%v, want:%v", got, newConfiguredIPv4Path)
	}
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv4().Address(newConfiguredIPv4Path).PrefixLength().State()); got != newConfiguredIPv4PrefixLength {
		t.Errorf("Negative IP prefix length configure failed! got:%v, want:%v", got, newConfiguredIPv4PrefixLength)
	}
}

// TestGNMIInbandSwIntfSetInvalidIPv6AddrAndPrefixLength -- Set and check IPv6 invalid address and invalid prefix length on the inband sw interface
func TestGNMIInbandSwIntfSetInvalidIPv6AddrOrPrefixLength(t *testing.T) {
	// Report results in TestTracker at the end
	defer testhelper.NewTearDownOptions(t).WithID("1e175d69-8968-4c0c-a34b-33d35969c9e0").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	d := &oc.Root{}
	iface := d.GetOrCreateInterface(inbandSwIntfName).GetOrCreateSubinterface(interfaceIndex)

	// Set invalid IPv6 address
	var invalidIPPath = "ffff:ffff:ffff:ffff:ffff:f567:67ff:befa:458f"
	newV6 := iface.GetOrCreateIpv6().GetOrCreateAddress(invalidIPPath)
	newV6.Ip = &invalidIPPath
	newV6.PrefixLength = &newConfiguredIPv6PrefixLength
	testt.ExpectFatal(t, func(t testing.TB) {
		gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(invalidIPPath).Config(), newV6)
	})

	// Verify the IPv6 address not changed.
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(newConfiguredIPv6Path).Ip().State()); got != newConfiguredIPv6Path {
		t.Errorf("Negative testing for IPv6 address configure failed! got:%v, want:%v", got, newConfiguredIPv6Path)
	}

	// Set IPv6 address with invalid prefix length for the loopback0 interface.
	var tryConfiguredIPv6Path = "3123::4567"
	var badConfiguredIPv6PrefixLength = uint8(80)
	newV6 = iface.GetOrCreateIpv6().GetOrCreateAddress(tryConfiguredIPv6Path)
	newV6.Ip = &tryConfiguredIPv6Path
	newV6.PrefixLength = &badConfiguredIPv6PrefixLength
	testt.ExpectFatal(t, func(t testing.TB) {
		gnmi.Replace(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(tryConfiguredIPv6Path).Config(), newV6)
	})

	// Verify the IPv6 address and prefix length are not changed.
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(newConfiguredIPv6Path).Ip().State()); got != newConfiguredIPv6Path {
		t.Errorf("Negative testing for IPv6 address configure failed! got:%v, want:%v", got, newConfiguredIPv6Path)
	}
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(inbandSwIntfName).Subinterface(interfaceIndex).Ipv6().Address(newConfiguredIPv6Path).PrefixLength().State()); got != newConfiguredIPv6PrefixLength {
		t.Errorf("Negative IPv6 prefix length configure failed! got:%v, want:%v", got, newConfiguredIPv6PrefixLength)
	}
}

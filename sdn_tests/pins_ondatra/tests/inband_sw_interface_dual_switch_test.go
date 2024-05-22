package inband_sw_interface_dual_switch_test

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

// These are the counters we track in these tests.
type counters struct {
	inPkts    uint64
	outPkts   uint64
	inOctets  uint64
	outOctets uint64
}

var (
	inbandSwIntfName           = "Loopback0"
	interfaceIndex             = uint32(0)
	configuredIPv4Path         = "6.7.8.9"
	configuredIPv4PrefixLength = uint8(32)
	configuredIPv6Path         = "3000::2"
	configuredIPv6PrefixLength = uint8(128)
	calledMockConfigPush       = false
)

// readCounters reads all the counters via GNMI and returns a counters struct.
func readCounters(t *testing.T, dut *ondatra.DUTDevice, intf string) *counters {
	t.Helper()
	cntStruct := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().State())
	return &counters{
		inPkts:    cntStruct.GetInPkts(),
		outPkts:   cntStruct.GetOutPkts(),
		inOctets:  cntStruct.GetInOctets(),
		outOctets: cntStruct.GetOutOctets(),
	}
}

// showCountersDelta shows debug info after an unexpected change in counters.
func showCountersDelta(t *testing.T, before *counters, after *counters, expect *counters) {
	t.Helper()

	for _, s := range []struct {
		desc                  string
		before, after, expect uint64
	}{
		{"in-pkts", before.inPkts, after.inPkts, expect.inPkts},
		{"out-pkts", before.outPkts, after.outPkts, expect.outPkts},
		{"in-octets", before.inOctets, after.inOctets, expect.inOctets},
		{"out-octets", before.outOctets, after.outOctets, expect.outOctets},
	} {
		if s.before != s.after || s.expect != s.before {
			t.Logf("%v %d -> %d expected %d (%+d)", s.desc, s.before, s.after, s.expect, s.after-s.before)
		}
	}
}

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

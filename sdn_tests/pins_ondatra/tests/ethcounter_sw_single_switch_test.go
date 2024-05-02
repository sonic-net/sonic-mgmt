// This file contains all the front panel port counter tests that can be
// done with a single switch, both egress (out) and ingress (in) if they
// can be done in loopback mode.  Tests requiring two switches or Ixia
// to accomplish are elsewhere.

package ethernet_counter_test

import (
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
)

// These are the counters we track in these tests.
type Counters struct {
	inPkts           uint64
	outPkts          uint64
	inOctets         uint64
	outOctets        uint64
	inUnicastPkts    uint64
	outUnicastPkts   uint64
	inMulticastPkts  uint64
	outMulticastPkts uint64
	inBroadcastPkts  uint64
	outBroadcastPkts uint64
	inErrors         uint64
	outErrors        uint64
	inDiscards       uint64
	outDiscards      uint64
	inMTUExceeded    uint64
	inIPv6Discards   uint64
	outIPv6Discards  uint64
}

var (
	initialMTU uint16 = 9100

	pktsPer uint64 = 7

	dmiWriteDelay time.Duration = 250 * time.Millisecond

	counterUpdateDelay time.Duration = 5000 * time.Millisecond
)

const (
	loopbackStateTimeout = 15 * time.Second
)

// Helper functions are here.

// CheckInitial validates preconditions before test starts.
func CheckInitial(t *testing.T, dut *ondatra.DUTDevice, intf string) {
	t.Helper()

	intfPath := gnmi.OC().Interface(intf)
	operStatus := gnmi.Get(t, dut, intfPath.OperStatus().State())

	if operStatus != oc.Interface_OperStatus_UP {
		t.Fatalf("%v OperStatus is unexpected: %v", intf, operStatus)
	}

	loopbackMode := gnmi.Get(t, dut, intfPath.LoopbackMode().State())
	if loopbackMode != oc.Interfaces_LoopbackModeType_NONE {
		gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_NONE)
		gnmi.Await(t, dut, intfPath.LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_NONE)
	}

	// Read the initial MTU to restore at test end.
	initialMTU = gnmi.Get(t, dut, intfPath.Mtu().State())
}

// RestoreInitial restores the initial conditions at the end of the test.
//
// This routine is called, deferred, at the start of the test to restore
// any conditions tests in this file might modify.
func RestoreInitial(t *testing.T, dut *ondatra.DUTDevice, intf string) {
	t.Helper()
	intfPath := gnmi.OC().Interface(intf)

	// Set loopback mode to false in case we changed it.
	loopbackMode := gnmi.Get(t, dut, intfPath.LoopbackMode().State())
	if loopbackMode != oc.Interfaces_LoopbackModeType_NONE {
		gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_NONE)
		gnmi.Await(t, dut, intfPath.LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_NONE)
	}

	// Restore the initial value of the MTU on the port.
	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), initialMTU)
	got := gnmi.Get(t, dut, intfPath.Mtu().State())
	if got != initialMTU {
		t.Fatalf("MTU restore failed! got:%v, want:%v", got, initialMTU)
	}
}

// ReadCounters reads all the counters via GNMI and returns a Counters struct.
func ReadCounters(t *testing.T, dut *ondatra.DUTDevice, intf string) Counters {
	t.Helper()

	c := Counters{}
	cntStruct := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().State())
	subPath := gnmi.OC().Interface(intf).Subinterface(0)
	ip6Struct := gnmi.Get(t, dut, subPath.Ipv6().Counters().State())
	c.inPkts = cntStruct.GetInPkts()
	c.outPkts = cntStruct.GetOutPkts()
	c.inOctets = cntStruct.GetInOctets()
	c.outOctets = cntStruct.GetOutOctets()
	c.inUnicastPkts = cntStruct.GetInUnicastPkts()
	c.outUnicastPkts = cntStruct.GetOutUnicastPkts()
	c.inMulticastPkts = cntStruct.GetInMulticastPkts()
	c.outMulticastPkts = cntStruct.GetOutMulticastPkts()
	c.inBroadcastPkts = cntStruct.GetInBroadcastPkts()
	c.outBroadcastPkts = cntStruct.GetOutBroadcastPkts()
	c.inErrors = cntStruct.GetInErrors()
	c.outErrors = cntStruct.GetOutErrors()
	c.inDiscards = cntStruct.GetInDiscards()
	c.outDiscards = cntStruct.GetOutDiscards()
	c.inIPv6Discards = ip6Struct.GetInDiscardedPkts()
	c.outIPv6Discards = ip6Struct.GetOutDiscardedPkts()
	c.inMTUExceeded = gnmi.Get(t, dut, gnmi.OC().Interface(intf).Ethernet().Counters().InMaxsizeExceeded().State())

	return c
}

// ShowCountersDelta shows debug info after an unexpected change in counters.
func ShowCountersDelta(t *testing.T, before Counters, after Counters, expect Counters) {
	t.Helper()

	for _, s := range []struct {
		desc                  string
		before, after, expect uint64
	}{
		{"in-pkts", before.inPkts, after.inPkts, expect.inPkts},
		{"out-pkts", before.outPkts, after.outPkts, expect.outPkts},
		{"in-octets", before.inOctets, after.inOctets, expect.inOctets},
		{"out-octets", before.outOctets, after.outOctets, expect.outOctets},
		{"in-unicast-pkts", before.inUnicastPkts, after.inUnicastPkts, expect.inUnicastPkts},
		{"out-unicast-pkts", before.outUnicastPkts, after.outUnicastPkts, expect.outUnicastPkts},
		{"in-multicast-pkts", before.inMulticastPkts, after.inMulticastPkts, expect.inMulticastPkts},
		{"out-multicast-pkts", before.outMulticastPkts, after.outMulticastPkts, expect.outMulticastPkts},
		{"in-broadcast-pkts", before.inBroadcastPkts, after.inBroadcastPkts, expect.inBroadcastPkts},
		{"out-broadcast-pkts", before.outBroadcastPkts, after.outBroadcastPkts, expect.outBroadcastPkts},
		{"in-errors", before.inErrors, after.inErrors, expect.inErrors},
		{"out-errors", before.outErrors, after.outErrors, expect.outErrors},
		{"in-discards", before.inDiscards, after.inDiscards, expect.inDiscards},
		{"out-discards", before.outDiscards, after.outDiscards, expect.outDiscards},
		{"in-mtu-exceeded", before.inMTUExceeded, after.inMTUExceeded, expect.inMTUExceeded},
		{"in-ipv6-discards", before.inIPv6Discards, after.inIPv6Discards, expect.inIPv6Discards},
		{"out-ipv6-discards", before.outIPv6Discards, after.outIPv6Discards, expect.outIPv6Discards},
	} {
		if s.before != s.after || s.expect != s.before {
			t.Logf("%v %d -> %d expected %d (%+d)", s.desc, s.before, s.after, s.expect, s.after-s.before)
		}
	}
}

// ----------------------------------------------------------------------------
// Tests start here.
func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

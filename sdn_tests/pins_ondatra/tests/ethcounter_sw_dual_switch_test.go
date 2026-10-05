package ethcounter_sw_dual_switch_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/pkg/errors"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
)

// These are the counters we track in these tests.
type counters struct {
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
	inIPv4Pkts       uint64
	outIPv4Pkts      uint64
	inIPv6Pkts       uint64
	outIPv6Pkts      uint64
	inMTUExceeded    uint64
	inIPv6Discards   uint64
	outIPv6Discards  uint64
}

var (
	initialMTU      uint16 = 9100
	initialLoopback        = oc.Interfaces_LoopbackModeType_NONE
)

const (
	pktsPer                  uint64 = 7
	counterUpdateDelay              = 3000 * time.Millisecond
	mtuStateTimeoutInSeconds        = 15
)

// Helper functions are here.

// controlPortLinkedToDutPort returns port on control switch that is connected to given port on DUT.
func controlPortLinkedToDUTPort(t *testing.T, dut *ondatra.DUTDevice, control *ondatra.DUTDevice, dutPort string) (string, error) {
	t.Helper()
	for _, port := range dut.Ports() {
		if port.Name() == dutPort {
			if control.Port(t, port.ID()) == nil {
				return "", errors.Errorf("control port corresponding to dutPort %v not found", dutPort)
			}
			return control.Port(t, port.ID()).Name(), nil
		}
	}
	return "", errors.Errorf("control port corresponding to dutPort %v not found", dutPort)
}

// checkInitial validates preconditions before test starts.
func checkInitial(t *testing.T, dut *ondatra.DUTDevice, intf string) {
	t.Helper()

	intfPath := gnmi.OC().Interface(intf)
	if operStatus := gnmi.Get(t, dut, intfPath.OperStatus().State()); operStatus != oc.Interface_OperStatus_UP {
		t.Fatalf("%v OperStatus is unexpected: %v", intf, operStatus)
	}

	if gnmi.Get(t, dut, intfPath.LoopbackMode().State()) != oc.Interfaces_LoopbackModeType_NONE {
		initialLoopback = oc.Interfaces_LoopbackModeType_FACILITY
		gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_NONE)
		gnmi.Await(t, dut, intfPath.LoopbackMode().State(), 5*time.Second, oc.Interfaces_LoopbackModeType_NONE)
	}

	// Read the initial MTU to restore at test end.
	initialMTU = gnmi.Get(t, dut, intfPath.Mtu().State())
}

// restoreInitial restores the initial conditions at the end of the test.
//
// This routine is called, deferred, at the start of the test to restore
// any conditions tests in this file might modify.
func restoreInitial(t *testing.T, dut *ondatra.DUTDevice, intf string) {
	t.Helper()
	intfPath := gnmi.OC().Interface(intf)

	// Set loopback mode to false in case we changed it.
	if loopbackMode := gnmi.Get(t, dut, intfPath.LoopbackMode().State()); loopbackMode != initialLoopback {
		gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), initialLoopback)
		gnmi.Await(t, dut, intfPath.LoopbackMode().State(), 5*time.Second, initialLoopback)
	}

	// Restore the initial value of the MTU on the port.
	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), initialMTU)
	gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), mtuStateTimeoutInSeconds*time.Second, initialMTU)
}

// readCounters reads all the counters via GNMI and returns a Counters struct.
func readCounters(t *testing.T, dut *ondatra.DUTDevice, intf string) counters {
	t.Helper()

	c := counters{}
	cntStruct := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().State())
	subPath := gnmi.OC().Interface(intf).Subinterface(0)
	ip4Struct := gnmi.Get(t, dut, subPath.Ipv4().Counters().State())
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
	c.inIPv4Pkts = ip4Struct.GetInPkts()
	c.outIPv4Pkts = ip4Struct.GetOutPkts()
	c.inIPv6Pkts = ip6Struct.GetInPkts()
	c.outIPv6Pkts = ip6Struct.GetOutPkts()
	c.inIPv6Discards = ip6Struct.GetInDiscardedPkts()
	c.outIPv6Discards = ip6Struct.GetOutDiscardedPkts()
	c.inMTUExceeded = gnmi.Get(t, dut, gnmi.OC().Interface(intf).Ethernet().Counters().InMaxsizeExceeded().State())

	return c
}

// showCountersDelta shows debug info after an unexpected change in counters.
func showCountersDelta(t *testing.T, before counters, after counters, expect counters) {
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
		{"in-mtu-exceeded", before.inMTUExceeded, after.inMTUExceeded, expect.inMTUExceeded},
		{"in-discards", before.inDiscards, after.inDiscards, expect.inDiscards},
		{"out-discards", before.outDiscards, after.outDiscards, expect.outDiscards},
		{"in-ipv4--pkts", before.inIPv4Pkts, after.inIPv4Pkts, expect.inIPv4Pkts},
		{"out-ipv4-pkts", before.outIPv4Pkts, after.outIPv4Pkts, expect.outIPv4Pkts},
		{"in-ipv6-pkts", before.inIPv6Pkts, after.inIPv6Pkts, expect.inIPv6Pkts},
		{"out-ipv6-pkts", before.outIPv6Pkts, after.outIPv6Pkts, expect.outIPv6Pkts},
		{"in-ipv6-discards", before.inIPv6Discards, after.inIPv6Discards, expect.inIPv6Discards},
		{"out-ipv6-discards", before.outIPv6Discards, after.outIPv6Discards, expect.outIPv6Discards},
	} {
		if s.before != s.after || s.expect != s.before {
			t.Logf("%v %d -> %d expected %d (%+d)", s.desc, s.before, s.after, s.expect, s.after-s.before)
		}
	}
}

// Tests start here.
func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

// TestGNMIEthernetInErrors - Check EthernetX In-Errors
func TestGNMIEthernetInErrors(t *testing.T) {
	t.Logf("\n\n\n\n\n----- TestGNMIEthernetInErrors  -----\n\n\n\n\n\n")

	// Report results to TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("4b8a5e02-7389-474a-a677-efde088667b0").WithID("fb11ecf4-6e74-4255-b150-4a30c2493c86").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	control := ondatra.DUT(t, "CONTROL")

	params := testhelper.RandomInterfaceParams{
		PortList: []string{
			dut.Port(t, "port1").Name(),
			dut.Port(t, "port2").Name(),
			dut.Port(t, "port3").Name(),
			dut.Port(t, "port4").Name(),
		}}

	dutIntf, err := testhelper.RandomInterface(t, dut, &params)
	if err != nil {
		t.Fatalf("Failed to fetch random interface on DUT: %v", err)
	}

	// Get the corresponding interface on control switch.
	controlIntf, err := controlPortLinkedToDUTPort(t, dut, control, dutIntf)
	if err != nil {
		t.Fatalf("Failed to get control port corresponding to DUT port %v: %v", dutIntf, err)
	}

	t.Logf("\n\nChose: dut %v control %v\n\n", dutIntf, controlIntf)

	// Check the initial state for this port on both switches.
	checkInitial(t, dut, dutIntf)
	defer restoreInitial(t, dut, dutIntf)
	checkInitial(t, control, controlIntf)
	defer restoreInitial(t, control, controlIntf)

	// Set the MTU for the dut switch port to 1500.
	var mtu uint16 = 1500
	gnmi.Replace(t, dut, gnmi.OC().Interface(dutIntf).Mtu().Config(), mtu)
	gnmi.Await(t, dut, gnmi.OC().Interface(dutIntf).Mtu().State(), mtuStateTimeoutInSeconds*time.Second, mtu)

	bad := false
	i := 0

	// Iterate up to 10 times to get a successful test.
	for i = 1; i <= 10; i++ {
		t.Logf("\n----- TestGNMIEthernetInErrors: Iteration %v -----\n", i)
		bad = false

		// Read all the relevant counters initial values.
		before := readCounters(t, dut, dutIntf)

		// Compute the expected counters after the test.
		expect := before
		expect.inErrors += pktsPer
		expect.inOctets += pktsPer * 2018
		expect.inMTUExceeded += pktsPer

		// Construct a simple oversize unicast Ethernet L2 packet.
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x00, 0x1A, 0x11, 0x17, 0x5F, 0x80},
			EthernetType: layers.EthernetTypeEthernetCTP,
		}

		data := make([]byte, 2000)
		for i := range data {
			data[i] = 0xfe
		}
		payload := gopacket.Payload(data)
		buf := gopacket.NewSerializeBuffer()

		// Enable reconstruction of length and checksum fields.
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		if err := gopacket.SerializeLayers(buf, opts, eth, payload); err != nil {
			t.Fatalf("Failed to serialize packet (%v)", err)
		}

		packetOut := &testhelper.PacketOut{
			EgressPort: controlIntf,
			Count:      uint(pktsPer),
			Interval:   1 * time.Millisecond,
			Packet:     buf.Bytes(),
		}

		p4rtClient, err := testhelper.FetchP4RTClient(t, control, control.RawAPIs().P4RT(t), nil)
		if err != nil {
			t.Fatalf("Failed to create P4RT client: %v", err)
		}
		if err := p4rtClient.SendPacketOut(t, packetOut); err != nil {
			t.Fatalf("SendPacketOut operation failed for %+v (%v)", packetOut, err)
		}

		// Sleep for enough time that the counters are polled after the
		// transmit completes sending bytes.  At 500ms we frequently
		// read the counters before they're updated.  Even at 1 second
		// I have seen counter increases show up on a subsequent
		// iteration rather than this one.
		time.Sleep(counterUpdateDelay)

		// Read all the relevant counters again.
		if after := readCounters(t, dut, dutIntf); after != expect {
			showCountersDelta(t, before, after, expect)
			if after != expect {
				bad = true
			}
		}

		if !bad {
			break
		}
	}

	if bad {
		t.Fatalf("\n\n----- TestGNMIEthernetInErrors: FAILED after %v Iterations -----\n\n", i-1)
	}

	t.Logf("\n\n----- TestGNMIEthernetInErrors: SUCCESS after %v Iteration(s) -----\n\n", i)
}

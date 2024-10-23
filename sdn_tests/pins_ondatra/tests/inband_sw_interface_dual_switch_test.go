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
	configuredIPv4Path         = "10.10.10.10"
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

// Tests start here.
func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

// TestGNMIInbandSwLoopbackInCnts - Check Loopback0 in-traffic counters
func TestGNMIInbandSwLoopbackInCnts(t *testing.T) {
	const (
		pktsPerTry         uint64 = 50
		counterUpdateDelay        = 1500 * time.Millisecond
		packetPayloadSize         = 1000
	)

	// Report results to TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("8e6b32f4-cf39-419f-ba36-db9c778ad317").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	control := ondatra.DUT(t, "CONTROL")
	mockConfigPush(t)

	// Select a random front panel interface EthernetX.
	params := testhelper.RandomInterfaceParams{
		PortList: []string{
			dut.Port(t, "port1").Name(),
			dut.Port(t, "port2").Name(),
			dut.Port(t, "port3").Name(),
			dut.Port(t, "port4").Name(),
		}}
	intf, err := testhelper.RandomInterface(t, dut, &params)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}

	bad := false
	i := 0

	// Iterate up to 5 times to get a successful test.
	for i = 1; i <= 5; i++ {
		t.Logf("\n----- TestGNMIInbandSwLoopbackInCnts: Iteration %v -----\n", i)
		bad = false

		// Read all the relevant counters initial values.
		before := readCounters(t, dut, inbandSwIntfName)

		// Construct packet.
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x00, 0x1a, 0x11, 0x17, 0x5f, 0x80},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.ParseIP("10.10.20.30").To4(),
			DstIP:    net.ParseIP(configuredIPv4Path).To4(),
		}
		tcp := &layers.TCP{
			SrcPort: 10000,
			DstPort: 22,
			Seq:     11050,
		}
		// Required for checksum computation.
		tcp.SetNetworkLayerForChecksum(ip)

		data := make([]byte, packetPayloadSize)
		for i := range data {
			data[i] = 0xfe
		}
		payload := gopacket.Payload(data)

		buf := gopacket.NewSerializeBuffer()

		// Enable reconstruction of length and checksum fields based on packet headers.
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, payload); err != nil {
			t.Fatalf("Failed to serialize packet (%v)", err)
		}

		// Compute the expected counters after the test.
		expect := before
		// Currently, counter increasing is not supported on loopback (b/197764888)
		// Uncomment below 2 lines when it becomes supported.
		// expect.inPkts += pktsPerTry
		// expect.inOctets += pktsPerTry * uint64(len(buf.Bytes()))

		packetOut := &testhelper.PacketOut{
			EgressPort: intf, // or "Ethernet8" for testing
			Count:      uint(pktsPerTry),
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
		// read the counters before they're updated.
		time.Sleep(counterUpdateDelay)

		// Read all the relevant counters again.
		if after := readCounters(t, dut, inbandSwIntfName); *after != *expect {
			showCountersDelta(t, before, after, expect)
			bad = true
		}

		if !bad {
			break
		}
	}

	if bad {
		t.Fatalf("\n\n----- TestGNMIInbandSwLoopbackInCnts: FAILED after %v Iterations -----\n\n", i-1)
	}

	t.Logf("\n\n----- TestGNMIInbandSwLoopbackInCnts: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// TestGNMIInbandSwLoopbackOutCnts - Check Loopback0 out-traffic counters
func TestGNMIInbandSwLoopbackOutCnts(t *testing.T) {
	const (
		pktsPerTry         uint64 = 50
		counterUpdateDelay        = 1500 * time.Millisecond
		packetPayloadSize         = 1000
	)

	// Report results to TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("57fbd43d-eeb3-478d-9740-69d9bb23fca6").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	// Select a random front panel interface EthernetX.
	params := testhelper.RandomInterfaceParams{
		PortList: []string{
			dut.Port(t, "port1").Name(),
			dut.Port(t, "port2").Name(),
			dut.Port(t, "port3").Name(),
			dut.Port(t, "port4").Name(),
		}}
	intf, err := testhelper.RandomInterface(t, dut, &params)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}

	bad := false
	i := 0

	// Iterate up to 5 times to get a successful test.
	for i = 1; i <= 5; i++ {
		t.Logf("\n----- TestGNMIInbandSwLoopbackOutCnts: Iteration %v -----\n", i)
		bad = false

		// Read all the relevant counters initial values.
		before := readCounters(t, dut, inbandSwIntfName)

		// Construct packet.
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x66, 0x77, 0x88},
			DstMAC:       net.HardwareAddr{0x00, 0x1a, 0x11, 0x17, 0x5f, 0x80},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.ParseIP(configuredIPv4Path).To4(),
			DstIP:    net.ParseIP("10.10.20.30").To4(),
		}
		tcp := &layers.TCP{
			SrcPort: 10000,
			DstPort: 22,
			Seq:     11050,
		}
		// Required for checksum computation.
		tcp.SetNetworkLayerForChecksum(ip)

		data := make([]byte, packetPayloadSize)
		for i := range data {
			data[i] = 0xfe
		}
		payload := gopacket.Payload(data)

		buf := gopacket.NewSerializeBuffer()

		// Enable reconstruction of length and checksum fields based on packet headers.
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, payload); err != nil {
			t.Fatalf("Failed to serialize packet (%v)", err)
		}

		// Compute the expected counters after the test.
		expect := before
		// Currently, counter increasing is not supported on loopback (b/197764888)
		// Uncomment below 2 lines when it becomes supported.
		// expect.inPkts += pktsPerTry
		// expect.inOctets += pktsPerTry * uint64(len(buf.Bytes()))

		packetOut := &testhelper.PacketOut{
			EgressPort: intf, // or "Ethernet8" for testing
			Count:      uint(pktsPerTry),
			Interval:   1 * time.Millisecond,
			Packet:     buf.Bytes(),
		}

		p4rtClient, err := testhelper.FetchP4RTClient(t, dut, dut.RawAPIs().P4RT(t), nil)
		if err != nil {
			t.Fatalf("Failed to create P4RT client: %v", err)
		}
		if err := p4rtClient.SendPacketOut(t, packetOut); err != nil {
			t.Fatalf("SendPacketOut operation failed for %+v (%v)", packetOut, err)
		}

		// Sleep for enough time that the counters are polled after the
		// transmit completes sending bytes.  At 500ms we frequently
		// read the counters before they're updated.
		time.Sleep(counterUpdateDelay)

		// Read all the relevant counters again.
		if after := readCounters(t, dut, inbandSwIntfName); *after != *expect {
			showCountersDelta(t, before, after, expect)
			bad = true
		}

		if !bad {
			break
		}
	}

	if bad {
		t.Fatalf("\n\n----- TestGNMIInbandSwLoopbackOutCnts: FAILED after %v Iterations -----\n\n", i-1)
	}

	t.Logf("\n\n----- TestGNMIInbandSwLoopbackOutCnts: SUCCESS after %v Iteration(s) -----\n\n", i)
}

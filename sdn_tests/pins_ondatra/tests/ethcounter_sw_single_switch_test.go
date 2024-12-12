// This file contains all the front panel port counter tests that can be
// done with a single switch, both egress (out) and ingress (in) if they
// can be done in loopback mode.  Tests requiring two switches or Ixia
// to accomplish are elsewhere.

package ethernet_counter_test

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

// ----------------------------------------------------------------------------
// TestGNMIEthernetInterfaceRole - Check EthernetX interface role.
// - management should be false
// - CPU should be false
func TestGNMIEthernetInterfaceRole(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("e0619932-46c8-4e49-9e2b-d79a67d03dea").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        intfPath := gnmi.OC().Interface(intf)

        // Read management via /state.  Note that the config path for
        // this doesn't exist since it's read-only.
        if stateMgmt := gnmi.Get(t, dut, intfPath.Management().State()); stateMgmt {
                t.Errorf("%v state Management is %v, wanted false", intf, stateMgmt)
        }

        // Read cpu via /state.
        if stateCPU := gnmi.Get(t, dut, intfPath.Cpu().State()); stateCPU {
                t.Errorf("%v state CPU is %v, wanted false", intf, stateCPU)
        }
}

// ----------------------------------------------------------------------------
// TestGNMIEthParentPaths - Check EthernetX counters and interface paths.
func TestGNMIEthParentPaths(t *testing.T) {
        // Reports results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("1aaa6fc9-da57-4751-89b1-56751ac209c6").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Pick a random interface, EthernetX
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        intfPath := gnmi.OC().Interface(intf)

        // Read all counters via /state.  The config path for
        // this doesn't exist since it's read-only.  The type
        // for the return value is "type Interface_Counters struct"
        stateCounters := gnmi.Get(t, dut, intfPath.Counters().State())

        // For most counters, simply require them not to be nil.
        if stateCounters.CarrierTransitions == nil {
                t.Errorf("%v CarrierTransitions wasn't nil", intf)
        }

        if stateCounters.InBroadcastPkts == nil {
                t.Errorf("%v BroadcastPkts is nil", intf)
        }

        if stateCounters.InDiscards == nil {
                t.Errorf("%v InDicards is nil", intf)
        }

        if stateCounters.InErrors == nil {
                t.Errorf("%v InErrors is nil", intf)
        }

        if stateCounters.InFcsErrors == nil {
                t.Errorf("%v InFcsErrors is nil", intf)
        }

        if stateCounters.InMulticastPkts == nil {
                t.Errorf("%v InMulticastPkts is nil", intf)
        }

        if stateCounters.InOctets == nil {
                t.Errorf("%v InOctets is nil", intf)
        }

        if stateCounters.InPkts == nil {
                t.Errorf("%v InPkts is nil", intf)
        }

        if stateCounters.InUnicastPkts == nil {
                t.Errorf("%v InUnicastPkts is nil", intf)
        }

        if stateCounters.InUnknownProtos == nil {
                t.Errorf("%v InUnknownProtos is nil", intf)
        }

        if stateCounters.LastClear == nil {
                t.Errorf("%v LastClear is nil", intf)
        }

        if stateCounters.OutBroadcastPkts == nil {
                t.Errorf("%v OutBroadcastPkts is nil", intf)
        }

        if stateCounters.OutDiscards == nil {
                t.Errorf("%v OutDiscards is nil", intf)
        }

        if stateCounters.OutErrors == nil {
                t.Errorf("%v OutErrors is nil", intf)
        }

        if stateCounters.OutMulticastPkts == nil {
                t.Errorf("%v OutMulticastPkts is nil", intf)
        }

        if stateCounters.OutOctets == nil {
                t.Errorf("%v OutOctets is nil", intf)
        }

        if stateCounters.OutPkts == nil {
                t.Errorf("%v OutPkts is nil", intf)
        }

        if stateCounters.OutUnicastPkts == nil {
                t.Errorf("%v OutUnicastPkts is nil", intf)
        }

        // Read parent via /state.  Note that the config path for
        // this doesn't exist since it is read-only.  The type
        // for the return value is
        // "type OpenconfigInterfaces_Interfaces_Interface_State struct"
        stateIntf := gnmi.Get(t, dut, intfPath.State())

        // Verify the information received.
        t.Logf("%v AdminStatus is %v", intf, stateIntf.AdminStatus)

        // Validate AdminStatus is UP.
        if stateIntf.AdminStatus != oc.Interface_AdminStatus_UP {
                t.Errorf("%v AdminStatus is unexpected: %v", intf, stateIntf.AdminStatus)
        }

        // Validate Counters is not nil.
        if stateIntf.Counters == nil {
                t.Errorf("%v Counters is nil", intf)
        }

        // Description may not be valid, allow. Typically ''.
        if stateIntf.Description != nil {
                t.Logf("%v Description is '%v'", intf, stateIntf.GetDescription())
        }

        // Validate Enabled.
        if stateIntf.Enabled == nil {
                t.Error("Ethernet0 Enabled is nil")
        } else {
                if !stateIntf.GetEnabled() {
                        t.Errorf("%v is not enabled", intf)
                }
        }

        // Ifindex may not be valid, allow.
        if stateIntf.Ifindex != nil {
                t.Logf("%v Ifindex is %v", intf, stateIntf.GetIfindex())
        }

        // LastChange may not be valid, allow.
        if stateIntf.LastChange != nil {
                t.Logf("%v LastChange is %v", intf, stateIntf.GetLastChange())
        }

        // Validate the LoopbackMode.
        if stateIntf.LoopbackMode == oc.Interfaces_LoopbackModeType_UNSET {
                t.Errorf("%v LoopbackMode is unset", intf)
        } else {
                if stateIntf.GetLoopbackMode() != oc.Interfaces_LoopbackModeType_NONE {
                        t.Errorf("LoopbackMode is not valid: got: %v, want: %v", stateIntf.GetLoopbackMode(), oc.Interfaces_LoopbackModeType_NONE)
                }
        }

        // Validate the MTU.
        if stateIntf.Mtu == nil {
                t.Errorf("%v Mtu is nil", intf)
        } else {
                if stateIntf.GetMtu() < 1500 || stateIntf.GetMtu() > 9216 {
                        t.Errorf("%v Mtu is unexpected: %v (expected [1514-9216]", intf, stateIntf.GetMtu())
                }
        }

        // Validate the Name.
        if stateIntf.Name == nil {
                t.Errorf("%v Name is nil", intf)
        } else {
                if stateIntf.GetName() != intf {
                        t.Errorf("%v Name is %v", intf, stateIntf.GetName())
                }
        }

        // Validate OperStatus.  Looks like links are often down in
        // current testbed so allow, at least for this test.
        if stateIntf.OperStatus != oc.Interface_OperStatus_UP {
                t.Logf("%v OperStatus is %v", intf, stateIntf.OperStatus)
        }

        // Validate the Type.
        if stateIntf.Type != oc.IETFInterfaces_InterfaceType_ethernetCsmacd {
                t.Errorf("%v Type is unexpected: %v", intf, stateIntf.Type)
        }
}

// ----------------------------------------------------------------------------
// TestGNMIEthSubinterfaceIndex - Check EthernetX subinterface index
func TestGNMIEthSubinterfaceIndex(t *testing.T) {
        // Reports results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("4a985794-a347-4bed-a50f-29a7f25b514f").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Pick a random interface, EthernetX
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        stateIndex := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Subinterface(0).Index().State())

        if stateIndex != 0 {
                t.Errorf("%v Subinterface Index is unexpected: %d", intf, stateIndex)
        }
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetOut - Check EthernetX Out-Pkts, Out-Octets and Out-Unicast-Pkts
// Because the systems we're testing on have existing traffic flowing at random
// intervals, we'll run the test a number of times looking for the expected
// changes.  If we get a run with the exact counter increments we expect then
// we exit successfully.  If we get a run with more changes than expected to
// the counters then we try again up to the limit.
func TestGNMIEthernetOut(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("c8eb77e8-12fd-44f9-a0fa-784b06d91491").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        CheckInitial(t, dut, intf)

        var bad bool
        var i int

        // Iterate up to 5 times to get a successful test.
        for i = 1; i <= 5; i++ {
                t.Logf("\n----- TestGNMIEthernetOut: Iteration %v -----\n", i)
                bad = false

                // Read all the relevant counters initial values.
                before := ReadCounters(t, dut, intf)

                // Compute the expected counters after the test.
                expect := before
                expect.outPkts += pktsPer
                expect.outOctets += 64 * pktsPer
                expect.outUnicastPkts += pktsPer

                // Construct a simple unicast Ethernet L2 packet.
                eth := &layers.Ethernet{
                        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                        DstMAC:       net.HardwareAddr{0x00, 0x1A, 0x11, 0x17, 0x5F, 0x80},
                        EthernetType: layers.EthernetTypeEthernetCTP,
                }

                buf := gopacket.NewSerializeBuffer()

                // Enable reconstruction of length and checksum fields.
                opts := gopacket.SerializeOptions{
                        FixLengths:       true,
                        ComputeChecksums: true,
                }

                if err := gopacket.SerializeLayers(buf, opts, eth); err != nil {
                        t.Fatalf("Failed to serialize packet (%v)", err)
                }

                packetOut := &testhelper.PacketOut{
                        EgressPort: intf,
                        Count:      uint(pktsPer),
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
                // read the counters before they're updated.  Even at 1 second
                // I have seen counter increases show up on a subsequent
                // iteration rather than this one.
                time.Sleep(counterUpdateDelay)

                // Read all the relevant counters again.
                after := ReadCounters(t, dut, intf)

                if after != expect {
                        ShowCountersDelta(t, before, after, expect)
                        bad = true
                }

                if !bad {
                        break
                }
        }

        if bad {
                t.Fatalf("\n\n----- TestGNMIEthernetOut: FAILED after %v Iterations -----\n\n", i-1)
        }
        t.Logf("\n\n----- TestGNMIEthernetOut: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetOutMulticast - Check EthernetX Out-Multicast-Pkts
func TestGNMIEthernetOutMulticast(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("a7bb8eb2-eb78-4658-926a-9f053f27adc6").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        CheckInitial(t, dut, intf)

        var bad bool
        var i int

        // Iterate up to 5 times to get a successful test.
        for i = 1; i <= 5; i++ {
                t.Logf("\n----- TestGNMIEthernetOutMulticast: Iteration %v -----\n", i)
                bad = false

                // Read all the relevant counters initial values.
                before := ReadCounters(t, dut, intf)

                // Compute the expected counters after the test.
                expect := before
                expect.outPkts += pktsPer
                expect.outOctets += 64 * pktsPer
                expect.outMulticastPkts += pktsPer


                // Construct a simple multicast Ethernet L2 packet.
                eth := &layers.Ethernet{
                        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                        DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5E, 0xFF, 0xFF, 0xFF},
                        EthernetType: layers.EthernetTypeEthernetCTP,
                }

                buf := gopacket.NewSerializeBuffer()

                // Enable reconstruction of length and checksum fields.
                opts := gopacket.SerializeOptions{
                        FixLengths:       true,
                        ComputeChecksums: true,
                }

                if err := gopacket.SerializeLayers(buf, opts, eth); err != nil {
                        t.Fatalf("Failed to serialize packet (%v)", err)
                }

                packetOut := &testhelper.PacketOut{
                        EgressPort: intf,
                        Count:      uint(pktsPer),
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
                // transmit completes sending bytes.
                time.Sleep(counterUpdateDelay)

                // Read all the relevant counters again.
                after := ReadCounters(t, dut, intf)

                if after != expect {
                        ShowCountersDelta(t, before, after, expect)
                        bad = true
                }

                if !bad {
                        break
                }
        }

        if bad {
                t.Fatalf("\n\n----- TestGNMIEthernetOutMulticast: FAILED after %v Iterations -----\n\n", i-1)
        }

        t.Logf("\n\n----- TestGNMIEthernetOutMulticast: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetOutBroadcast - Check EthernetX Out-Broadcast-Pkts
func TestGNMIEthernetOutBroadcast(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("3ffe7160-82df-4b91-b41a-bc6c582aa237").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        CheckInitial(t, dut, intf)

        var bad bool
        var i int

        // Iterate up to 5 times to get a successful test.
        for i = 1; i <= 5; i++ {
                t.Logf("\n----- TestGNMIEthernetOutBroadcast: Iteration %v -----\n", i)
                bad = false

                // Read all the relevant counters initial values.
                before := ReadCounters(t, dut, intf)

                // Compute the expected counters after the test.
                expect := before
                expect.outPkts += pktsPer
                expect.outOctets += 64 * pktsPer
                expect.outBroadcastPkts += pktsPer

                // Construct a simple broadcast Ethernet L2 packet.
                eth := &layers.Ethernet{
                        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                        DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                        EthernetType: layers.EthernetTypeEthernetCTP,
                }

                buf := gopacket.NewSerializeBuffer()

                // Enable reconstruction of length and checksum fields.
                opts := gopacket.SerializeOptions{
                        FixLengths:       true,
                        ComputeChecksums: true,
                }

                if err := gopacket.SerializeLayers(buf, opts, eth); err != nil {
                        t.Fatalf("Failed to serialize packet (%v)", err)
                }

                packetOut := &testhelper.PacketOut{
                        EgressPort: intf,
                        Count:      uint(pktsPer),
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
                // transmit completes sending bytes.
                time.Sleep(counterUpdateDelay)

                // Read all the relevant counters again.
                after := ReadCounters(t, dut, intf)

                if after != expect {
                        ShowCountersDelta(t, before, after, expect)
                        bad = true
                }

                if !bad {
                        break
                }
        }

        if bad {
                t.Fatalf("\n\n----- TestGNMIEthernetOutBroadcast: FAILED after %v Iterations -----\n\n", i-1)
        }

        t.Logf("\n\n----- TestGNMIEthernetOutBroadcast: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetIn - Check EthernetX In-Pkts, In-Octets and In-Unicast-Pkts
func TestGNMIEthernetIn(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("1c509238-e94b-4dab-aa1b-f47683a5b302").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        CheckInitial(t, dut, intf)
        defer RestoreInitial(t, dut, intf)

        // To get ingress traffic in Ondatra, turn on loopback mode on
        // the selected port just for this test.
        gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_FACILITY)
        gnmi.Await(t, dut, gnmi.OC().Interface(intf).LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_FACILITY)

        var bad bool
        var i int

        // Iterate up to 10 times to get a successful test.
        for i = 1; i <= 10; i++ {
                t.Logf("\n----- TestGNMIEthernetIn: Iteration %v -----\n", i)
                bad = false

                // Read all the relevant counters initial values.
                before := ReadCounters(t, dut, intf)

                // Compute the expected counters after the test.
                expect := before
                expect.outPkts += pktsPer
                expect.outOctets += 64 * pktsPer
                expect.outUnicastPkts += pktsPer
                expect.inPkts += pktsPer
                expect.inOctets += 64 * pktsPer
                expect.inUnicastPkts += pktsPer

                // Construct a simple unicast Ethernet L2 packet.
                eth := &layers.Ethernet{
                        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                        DstMAC:       net.HardwareAddr{0x00, 0x1A, 0x11, 0x17, 0x5F, 0x80},
                        EthernetType: layers.EthernetTypeEthernetCTP,
                }

                buf := gopacket.NewSerializeBuffer()

                // Enable reconstruction of length and checksum fields.
                opts := gopacket.SerializeOptions{
                        FixLengths:       true,
                        ComputeChecksums: true,
                }

                if err := gopacket.SerializeLayers(buf, opts, eth); err != nil {
                        t.Fatalf("Failed to serialize packet (%v)", err)
                }

                packetOut := &testhelper.PacketOut{
                        EgressPort: intf,
                        Count:      uint(pktsPer),
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
                // transmit completes sending bytes.
                time.Sleep(counterUpdateDelay)

                // Read all the relevant counters again.
                after := ReadCounters(t, dut, intf)

                // We're seeing some random discards during testing due to
                // existing traffic being discarded in loopback mode so simply
                // set up to ignore them.
                expect.inDiscards = after.inDiscards

                if after != expect {
                        ShowCountersDelta(t, before, after, expect)
                        bad = true
                }

                if !bad {
                        break
                }
        }

        if bad {
                t.Fatalf("\n\n----- TestGNMIEthernetIn: FAILED after %v Iterations -----\n\n", i-1)
        }

        t.Logf("\n\n----- TestGNMIEthernetIn: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetInMulticast - Check EthernetX In-Multicast-Pkts
func TestGNMIEthernetInMulticast(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("0b34a2a3-4b30-41cf-a642-634334357cee").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        CheckInitial(t, dut, intf)
        defer RestoreInitial(t, dut, intf)

        // To get ingress traffic in Ondatra, turn on loopback mode on
        // the selected port just for this test.
        gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_FACILITY)
        gnmi.Await(t, dut, gnmi.OC().Interface(intf).LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_FACILITY)

        var bad bool
        var i int

        // Iterate up to 10 times to get a successful test.
        for i = 1; i <= 10; i++ {
                t.Logf("\n----- TestGNMIEthernetInMulticast: Iteration %v -----\n", i)
                bad = false

                // Read all the relevant counters initial values.
                before := ReadCounters(t, dut, intf)

                // Compute the expected counters after the test.
                expect := before
                expect.outPkts += pktsPer
                expect.outOctets += 64 * pktsPer
                expect.outMulticastPkts += pktsPer
                expect.inPkts += pktsPer
                expect.inOctets += 64 * pktsPer
                expect.inMulticastPkts += pktsPer

                // Construct a simple multicast Ethernet L2 packet.
                eth := &layers.Ethernet{
                        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                        DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5E, 0xFF, 0xFF, 0xFF},
                        EthernetType: layers.EthernetTypeEthernetCTP,
                }

                buf := gopacket.NewSerializeBuffer()

                // Enable reconstruction of length and checksum fields.
                opts := gopacket.SerializeOptions{
                        FixLengths:       true,
                        ComputeChecksums: true,
                }

                if err := gopacket.SerializeLayers(buf, opts, eth); err != nil {
                        t.Fatalf("Failed to serialize packet (%v)", err)
                }

                packetOut := &testhelper.PacketOut{
                        EgressPort: intf,
                        Count:      uint(pktsPer),
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
                // transmit completes sending bytes.
                time.Sleep(counterUpdateDelay)

                // Read all the relevant counters again.
                after := ReadCounters(t, dut, intf)

                // We're seeing some random discards during testing due to
                // existing traffic being discarded in loopback mode so simply
                // set up to ignore them.
                expect.inDiscards = after.inDiscards

                if after != expect {
                        ShowCountersDelta(t, before, after, expect)
                        bad = true
                }

                if !bad {
                        break
                }
        }

        if bad {
                t.Fatalf("\n\n----- TestGNMIEthernetInMulticast: FAILED after %v Iterations -----\n\n", i-1)
        }

        t.Logf("\n\n----- TestGNMIEthernetInMulticast: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetInBroadcast - Check EthernetX In-Broadcast-Pkts
func TestGNMIEthernetInBroadcast(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("334c1369-b12f-4f73-aec1-effbb0a3fd4b").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        CheckInitial(t, dut, intf)
        defer RestoreInitial(t, dut, intf)

        // To get ingress traffic in Ondatra, turn on loopback mode on
        // the selected port just for this test.
        gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_FACILITY)
        gnmi.Await(t, dut, gnmi.OC().Interface(intf).LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_FACILITY)

        var bad bool
        var i int

        // Iterate up to 10 times to get a successful test.
        for i = 1; i <= 10; i++ {
                t.Logf("\n----- TestGNMIEthernetInBroadcast: Iteration %v -----\n", i)
                bad = false

                // Read all the relevant counters initial values.
                before := ReadCounters(t, dut, intf)

                // Compute the expected counters after the test.
                expect := before
                expect.outPkts += pktsPer
                expect.outOctets += 64 * pktsPer
                expect.outBroadcastPkts += pktsPer
                expect.inPkts += pktsPer
                expect.inOctets += 64 * pktsPer
                expect.inBroadcastPkts += pktsPer

                // Construct a simple multicast Ethernet L2 packet.
                eth := &layers.Ethernet{
                        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                        DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                        EthernetType: layers.EthernetTypeEthernetCTP,
                }

                buf := gopacket.NewSerializeBuffer()

                // Enable reconstruction of length and checksum fields.
                opts := gopacket.SerializeOptions{
                        FixLengths:       true,
                        ComputeChecksums: true,
                }

                if err := gopacket.SerializeLayers(buf, opts, eth); err != nil {
                        t.Fatalf("Failed to serialize packet (%v)", err)
                }

                packetOut := &testhelper.PacketOut{
                        EgressPort: intf,
                        Count:      uint(pktsPer),
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
                // transmit completes sending bytes.
                time.Sleep(counterUpdateDelay)

                // Read all the relevant counters again.
                after := ReadCounters(t, dut, intf)

                // We're seeing some random discards during testing due to
                // existing traffic being discarded in loopback mode so simply
                // set up to ignore them.
                expect.inDiscards = after.inDiscards

                if after != expect {
                        ShowCountersDelta(t, before, after, expect)
                        bad = true
                }

                if !bad {
                        break
                }
        }

        if bad {
                t.Fatalf("\n\n----- TestGNMIEthernetInBroadcast: FAILED after %v Iterations -----\n\n", i-1)
        }

        t.Logf("\n\n----- TestGNMIEthernetInBroadcast: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetInIPv4Pkts - Check EthernetX Subinterface IPv4 in-pkts
func TestGNMIEthernetInIPv4(t *testing.T) {
	// Report results to TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("8e134557-a159-44ba-9005-e67c7bf8744c").Teardown(t)

	// Select the dut, or device under test.
	dut := ondatra.DUT(t, "DUT")

	// Select a random front panel interface EthernetX.
	intf, err := testhelper.RandomInterface(t, dut, nil)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}
	CheckInitial(t, dut, intf)
	defer RestoreInitial(t, dut, intf)

	// To get ingress traffic in Ondatra, turn on loopback mode on
	// the selected port just for this test.
	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_FACILITY)
	gnmi.Await(t, dut, gnmi.OC().Interface(intf).LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_FACILITY)

	var bad bool
	var i int

	// Iterate up to 10 times to get a successful test.
	for i = 1; i <= 10; i++ {
		t.Logf("\n----- TestGNMIEthernetInIPv4: Iteration %v -----\n", i)
		bad = false

		// Read all the relevant counters initial values.
		before := ReadCounters(t, dut, intf)

		// Compute the expected counters after the test.
		expect := before
		expect.outPkts += pktsPer
		expect.outOctets += 64 * pktsPer
		expect.outUnicastPkts += pktsPer
		expect.inPkts += pktsPer
		expect.inOctets += 64 * pktsPer
		expect.inUnicastPkts += pktsPer

		// Construct a simple IPv4 packet.
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x00, 0x1A, 0x11, 0x17, 0x5F, 0x80},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.ParseIP("100.0.0.1").To4(),
			DstIP:    net.ParseIP("200.0.0.1").To4(),
		}
		tcp := &layers.TCP{
			SrcPort: 10000,
			DstPort: 20000,
			Seq:     11050,
		}
		// Required for checksum computation.
		tcp.SetNetworkLayerForChecksum(ip)
		payload := gopacket.Payload([]byte{'t', 'e', 's', 't'})
		buf := gopacket.NewSerializeBuffer()

		// Enable reconstruction of length and checksum fields based on packet headers.
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, payload); err != nil {
			t.Fatalf("Failed to serialize packet (%v)", err)
		}

		packetOut := &testhelper.PacketOut{
			EgressPort: intf,
			Count:      uint(pktsPer),
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
		// transmit completes sending bytes.
		time.Sleep(counterUpdateDelay)

		// Read all the relevant counters again.
		after := ReadCounters(t, dut, intf)

		// We're seeing some random discards during testing due to
		// existing traffic being discarded in loopback mode so simply
		// set up to ignore them.
		expect.inDiscards = after.inDiscards

		if after != expect {
			ShowCountersDelta(t, before, after, expect)
			bad = true
		}

		if !bad {
			break
		}
	}

	if bad {
		t.Fatalf("\n\n----- TestGNMIEthernetInIPv4: FAILED after %v Iterations -----\n\n", i-1)
	}

	t.Logf("\n\n----- TestGNMIEthernetInIPv4: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetInIPv6Pkts - Check EthernetX Subinterface IPv6 in-pkts
func TestGNMIEthernetInIPv6(t *testing.T) {
	// Report results to TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("bb5e6b9f-404d-441d-9a0b-a2ecb9785e1a").Teardown(t)

	// Select the dut, or device under test.
	dut := ondatra.DUT(t, "DUT")

	// Select a random front panel interface EthernetX.
	intf, err := testhelper.RandomInterface(t, dut, nil)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}
	CheckInitial(t, dut, intf)
	defer RestoreInitial(t, dut, intf)

	// To get ingress traffic in Ondatra, turn on loopback mode on
	// the selected port just for this test.
	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_FACILITY)
	gnmi.Await(t, dut, gnmi.OC().Interface(intf).LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_FACILITY)

	var bad bool
	var i int

	// Iterate up to 10 times to get a successful test.
	for i = 1; i <= 10; i++ {
		t.Logf("\n----- TestGNMIEthernetInIPv6: Iteration %v -----\n", i)
		bad = false
		// Read all the relevant counters initial values.
		before := ReadCounters(t, dut, intf)

		// Compute the expected counters after the test.
		expect := before
		expect.outPkts += pktsPer
		expect.outOctets += 64 * pktsPer
		expect.outUnicastPkts += pktsPer
		expect.inPkts += pktsPer
		expect.inOctets += 64 * pktsPer
		expect.inUnicastPkts += pktsPer

		// Construct a simple IPv6 packet.
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x00, 0x1A, 0x11, 0x17, 0x5F, 0x80},
			EthernetType: layers.EthernetTypeIPv6,
		}
		ip := &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			SrcIP:      net.ParseIP("2001:db8::1"),
			DstIP:      net.ParseIP("2001:db8::2"),
			NextHeader: layers.IPProtocolICMPv6,
		}
		icmp := &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypePacketTooBig, 0),
		}

		icmp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()

		// Enable reconstruction of length and checksum fields based on packet headers.
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp); err != nil {
			t.Fatalf("Failed to serialize packet (%v)", err)
		}

		packetOut := &testhelper.PacketOut{
			EgressPort: intf,
			Count:      uint(pktsPer),
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
		// transmit completes sending bytes.
		time.Sleep(counterUpdateDelay)

		// Read all the relevant counters again.
		after := ReadCounters(t, dut, intf)

		// We're seeing some random discards during testing due to
		// existing traffic being discarded in loopback mode so simply
		// set up to ignore them.
		expect.inDiscards = after.inDiscards

		if after != expect {
			ShowCountersDelta(t, before, after, expect)
			bad = true
		}

		if !bad {
			break
		}
	}

	if bad {
		t.Fatalf("\n\n----- TestGNMIEthernetInIPv6: FAILED after %v Iterations -----\n\n", i-1)
	}

	t.Logf("\n\n----- TestGNMIEthernetInIPv6: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetInDiscards - Check EthernetX in-discards
func TestGNMIEthernetInDiscards(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("dde5578a-33f2-40b2-a7fa-a978b9ee0a51").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        CheckInitial(t, dut, intf)
        defer RestoreInitial(t, dut, intf)

        // To get ingress traffic in Ondatra, turn on loopback mode on
        // the selected port just for this test.
        gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_FACILITY)
        gnmi.Await(t, dut, gnmi.OC().Interface(intf).LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_FACILITY)

        var bad bool
        var i int

        // Iterate up to 10 times to get a successful test.
        for i = 1; i <= 10; i++ {
                t.Logf("\n----- TestGNMIEthernetInDiscards: Iteration %v -----\n", i)
                bad = false

                // Read all the relevant counters initial values.
                before := ReadCounters(t, dut, intf)

                // Compute the expected counters after the test. Since
                // we're seeing some discard traffic (1 or 2 per second) during
                // normal operation on the Ondatra testbeds with loopback
                // turned on, setting the number of packets to be sent larger
                // so we can actually verify its those packets that we got.
                expect := before
                expect.outPkts += pktsPer
                expect.outOctets += pktsPer * 64
                expect.outUnicastPkts += pktsPer
                expect.inPkts += pktsPer
                expect.inOctets += pktsPer * 64
                expect.inUnicastPkts += pktsPer
                expect.inDiscards += pktsPer

                // Construct a simple IPv4 packet that will get discarded.  In
                // offline testing, setting the IP protocol field to zero
                // worked to cause a discard on ingest.
                eth := &layers.Ethernet{
                        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                        DstMAC:       net.HardwareAddr{0x00, 0x1A, 0x11, 0x17, 0x5F, 0x80},
                        EthernetType: layers.EthernetTypeIPv4,
                }

                ip := &layers.IPv4{
                        Version:  4,
                        TTL:      0,
                        Protocol: layers.IPProtocol(0),
                        SrcIP:    net.ParseIP("100.0.0.1").To4(),
                        DstIP:    net.ParseIP("200.0.0.1").To4(),
                }

                buf := gopacket.NewSerializeBuffer()

                // Enable reconstruction of length and checksum fields based on packet headers.
                opts := gopacket.SerializeOptions{
                        FixLengths:       true,
                        ComputeChecksums: true,
                }

                if err := gopacket.SerializeLayers(buf, opts, eth, ip); err != nil {
                        t.Fatalf("Failed to serialize packet (%v)", err)
                }

                packetOut := &testhelper.PacketOut{
                        EgressPort: intf,
                        Count:      uint(pktsPer),
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
                // transmit completes sending bytes.
                time.Sleep(counterUpdateDelay)

                // Read all the relevant counters again.
                after := ReadCounters(t, dut, intf)

                if after != expect {
                        ShowCountersDelta(t, before, after, expect)
                        bad = true
                }

                if !bad {
                        break
                }
        }

        if bad {
                t.Fatalf("\n\n----- TestGNMIEthernetInDiscards: FAILED after %v Iterations -----\n\n", i-1)
        }

        t.Logf("\n\n----- TestGNMIEthernetInDiscards: SUCCESS after %v Iteration(s) -----\n\n", i)
}

// ----------------------------------------------------------------------------
// TestGNMIEthernetInIPv6Discards - Check EthernetX Subinterface in-ipv6-discards
func TestGNMIEthernetInIPv6Discards(t *testing.T) {
        // Report results to TestTracker at the end.
        defer testhelper.NewTearDownOptions(t).WithID("2b04e2cb-cce4-43ef-ad42-5cef4dc8f55c").Teardown(t)

        // Select the dut, or device under test.
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        CheckInitial(t, dut, intf)
        defer RestoreInitial(t, dut, intf)

        // To get ingress traffic in Ondatra, turn on loopback mode on
        // the selected port just for this test.
        gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), oc.Interfaces_LoopbackModeType_FACILITY)
        gnmi.Await(t, dut, gnmi.OC().Interface(intf).LoopbackMode().State(), loopbackStateTimeout, oc.Interfaces_LoopbackModeType_FACILITY)

        var bad bool
        var i int

        // Iterate up to 10 times to get a successful test.
        for i = 1; i <= 10; i++ {
                t.Logf("\n----- TestGNMIEthernetInIPv6Discards: Iteration %v -----\n", i)
                bad = false

                // Read all the relevant counters initial values.
                before := ReadCounters(t, dut, intf)

                // Compute the expected counters after the test.. Since
                // we're seeing some discard traffic (1 or 2 per second) during
                // normal operation on the Ondatra testbeds with loopback
                // turned on, setting the number of packets to be sent larger
                // so we can actually verify its those packets that we got.
                expect := before
                expect.outPkts += pktsPer
                expect.outOctets += pktsPer * 64
                expect.outUnicastPkts += pktsPer
                expect.inPkts += pktsPer
                expect.inOctets += pktsPer * 64
                expect.inUnicastPkts += pktsPer
                expect.inDiscards += pktsPer
                expect.inIPv6Discards += pktsPer

                // Construct a simple IPv6 packet that will get discarded.
                // Construct a simple IPv6 packet.
                eth := &layers.Ethernet{
                        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                        DstMAC:       net.HardwareAddr{0x00, 0x1A, 0x11, 0x17, 0x5F, 0x80},
                        EthernetType: layers.EthernetTypeIPv6,
                }

                ip := &layers.IPv6{
                        Version:    6,
                        HopLimit:   0,
                        SrcIP:      net.ParseIP("2001:db8::1"),
                        DstIP:      net.ParseIP("2001:db8::2"),
                        NextHeader: layers.IPProtocol(0),
                }

                buf := gopacket.NewSerializeBuffer()

                // Enable reconstruction of length and checksum fields based on packet headers.
                opts := gopacket.SerializeOptions{
                        FixLengths:       true,
                        ComputeChecksums: true,
                }

                if err := gopacket.SerializeLayers(buf, opts, eth, ip); err != nil {
                        t.Fatalf("Failed to serialize packet (%v)", err)
                }

                packetOut := &testhelper.PacketOut{
                        EgressPort: intf,
                        Count:      uint(pktsPer),
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
                // transmit completes sending bytes.
                time.Sleep(counterUpdateDelay)

                // Read all the relevant counters again.
                after := ReadCounters(t, dut, intf)

                if after != expect {
                        ShowCountersDelta(t, before, after, expect)
                        bad = true
                }

                if !bad {
                        break
                }
        }

        if bad {
                t.Fatalf("\n\n----- TestGNMIEthernetInIPv6Discards: FAILED after %v Iterations -----\n\n", i-1)
        }

        t.Logf("\n\n----- TestGNMIEthernetInIPv6Discards: SUCCESS after %v Iteration(s) -----\n\n", i)
}

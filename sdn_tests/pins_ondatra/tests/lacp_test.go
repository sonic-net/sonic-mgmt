package lacp_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"github.com/pkg/errors"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
)

// gNMI can cache local state for up to 10 seconds. We therefore set our timeout to a little longer
// to handle any edge cases when verifying state.
const defaultGNMIWait = 15 * time.Second

// IEEE 802.3ad defines the Link Aggregation standard used by LACP where connected ports can
// experimental control packets between each other. Based on these packets the switch can group matching
// ports into a LAG/Trunk/PortChannel.
//
// Local state is maintained for each member of a LAG to monitor the health of that given member.
type lacpMemberState struct {
	activity        oc.E_Lacp_LacpActivityType
	timeout         oc.E_Lacp_LacpTimeoutType
	aggregatable    bool
	synchronization oc.E_Lacp_LacpSynchronizationType
	collecting      bool
	distributing    bool
}

// Wait for the switch state of a specific PortChannel member to converge to a users expectations.
// If the switch state does not converge return a string detailing the difference between the final
// state received, and what the user wanted.
func compareLacpMemberState(t *testing.T, dut *ondatra.DUTDevice, pcName string, memberName string, want lacpMemberState) string {
	t.Helper()

	// Wait for the switch value to match our expectation.
	predicate := func(val *ygnmi.Value[*oc.Lacp_Interface_Member]) bool {
		currentVal, present := val.Val()
		if !present {
			return false
		}
		return currentVal.GetActivity() == want.activity &&
			currentVal.GetTimeout() == want.timeout &&
			currentVal.GetAggregatable() == want.aggregatable &&
			currentVal.GetSynchronization() == want.synchronization &&
			currentVal.GetCollecting() == want.collecting &&
			currentVal.GetDistributing() == want.distributing
	}
	lastVal, match := gnmi.Watch(t, dut, gnmi.OC().Lacp().Interface(pcName).Member(memberName).State(), defaultGNMIWait, predicate).Await(t)

	state, ok := lastVal.Val()
	if !ok {
		return "no value for lacp interface member"
	}
	var diff strings.Builder
	if !match {
		fmt.Fprintf(&diff, "%v:%v:%v (-want, +got)", dut.Name(), pcName, memberName)

		if state.Activity == want.activity {
			fmt.Fprintf(&diff, "\nactivity:        %v", state.Activity)
		} else if state.Activity == oc.Lacp_LacpActivityType_UNSET {
			fmt.Fprintf(&diff, "\nactivity:        -%v, +(unset)", want.activity)
		} else {
			fmt.Fprintf(&diff, "\nactivity:        -%v, +%v", want.activity, state.Activity)
		}

		if state.Timeout == want.timeout {
			fmt.Fprintf(&diff, "\ntimeout:         %v", state.Timeout)
		} else if state.Timeout == oc.Lacp_LacpTimeoutType_UNSET {
			fmt.Fprintf(&diff, "\ntimeout:         -%v, +(unset)", want.timeout)
		} else {
			fmt.Fprintf(&diff, "\ntimeout:         -%v, +%v", want.timeout, state.Timeout)
		}

		if state.Aggregatable != nil && *state.Aggregatable == want.aggregatable {
			fmt.Fprintf(&diff, "\naggregatable:    %v", *state.Aggregatable)
		} else if state.Aggregatable == nil {
			fmt.Fprintf(&diff, "\naggregatable:    -%v, +(unset)", want.aggregatable)
		} else {
			fmt.Fprintf(&diff, "\naggregatable:    -%v, +%v", want.aggregatable, *state.Aggregatable)
		}

		if state.Synchronization == want.synchronization {
			fmt.Fprintf(&diff, "\nsynchronization: %v", state.Synchronization)
		} else if state.Synchronization == oc.Lacp_LacpSynchronizationType_UNSET {
			fmt.Fprintf(&diff, "\nsynchronization: -%v, +(unset)", want.synchronization)
		} else {
			fmt.Fprintf(&diff, "\nsynchronization: -%v, +%v", want.synchronization, state.Synchronization)
		}

		if state.Collecting != nil && *state.Collecting == want.collecting {
			fmt.Fprintf(&diff, "\ncollecting:      %v", state.Collecting)
		} else if state.Collecting == nil {
			fmt.Fprintf(&diff, "\ncollecting:      -%v, +(unset)", want.collecting)
		} else {
			fmt.Fprintf(&diff, "\ncollecting:      -%v, -%v", want.collecting, *state.Collecting)
		}

		if state.Distributing != nil && *state.Distributing == want.distributing {
			fmt.Fprintf(&diff, "\ndistributing:    %v", *state.Distributing)
		} else if state.Distributing == nil {
			fmt.Fprintf(&diff, "\ndistributing:    -%v, +(unset)", want.distributing)
		} else {
			fmt.Fprintf(&diff, "\ndistributing:    -%v, +%v", want.distributing, *state.Distributing)
		}
	}
	return diff.String()
}

// Blocking state happens when one side of the LACP connection is up, but the other is not. For
// example, a port is down, or not yet configured. When this happens we expect the member to still
// be active and aggregatable (i.e. waiting for the other end to come up), but not yet in-sync or
// collecting/distributing traffic.
func verifyBlockingState(t *testing.T, dut *ondatra.DUTDevice, pcName string, memberName string) error {
	t.Helper()

	want := lacpMemberState{
		activity:        oc.Lacp_LacpActivityType_ACTIVE,
		timeout:         oc.Lacp_LacpTimeoutType_LONG,
		aggregatable:    true,
		synchronization: oc.Lacp_LacpSynchronizationType_OUT_SYNC,
		collecting:      false,
		distributing:    false,
	}

	// gNMI does not support ON_CHANGE events for LACP paths, and SAMPLING can fatally fail if an
	// entry doesn't yet exist (i.e. we call this too quickly after sending a config). So to prevent
	// flakes we run this check twice in a row.
	if firstDiff := compareLacpMemberState(t, dut, pcName, memberName, want); firstDiff != "" {
		log.Warningf("Failed first blocking check: %s", firstDiff)
		if secondDiff := compareLacpMemberState(t, dut, pcName, memberName, want); secondDiff != "" {
			return errors.New(secondDiff)
		}
	}
	return nil
}

// In-Sync state happens when both side of the LACP connection are up and healthy. When in this
// state we expect the member to be active, aggregatable, in-sync, collecting, and distributing
// traffic.
func verifyInSyncState(t *testing.T, dut *ondatra.DUTDevice, pcName string, memberName string) error {
	t.Helper()

	want := lacpMemberState{
		activity:        oc.Lacp_LacpActivityType_ACTIVE,
		timeout:         oc.Lacp_LacpTimeoutType_LONG,
		aggregatable:    true,
		synchronization: oc.Lacp_LacpSynchronizationType_IN_SYNC,
		collecting:      true,
		distributing:    true,
	}

	// gNMI does not support ON_CHANGE events for LACP paths, and SAMPLING can fatally fail if an
	// entry doesn't yet exist (i.e. we call this too quickly after sending a config). So to prevent
	// flakes we run this check twice in a row.
	if firstDiff := compareLacpMemberState(t, dut, pcName, memberName, want); firstDiff != "" {
		log.Warningf("Failed first in-sync check: %s", firstDiff)
		if secondDiff := compareLacpMemberState(t, dut, pcName, memberName, want); secondDiff != "" {
			return errors.New(secondDiff)
		}
	}
	return nil
}

// gNMI does not specify an ordering for the member list of a PortChannel. To make tests
// reproducible we need to sort the member lists before comparing.
func comparePortChannelMemberList(t *testing.T, timeout time.Duration, dut *ondatra.DUTDevice, pcName string, members []string) error {
	t.Helper()

	// Users do not have to pre-sort their list.
	sort.Strings(members)

	predicate := func(val *ygnmi.Value[[]string]) bool {
		got, present := val.Val()
		// If the value isn't present then simply return false.
		if !present {
			return false
		}

		// Otherwise, sort the values from the switch, and compare them to the expectations.
		sort.Strings(got)
		return cmp.Equal(members, got)
	}

	// gNMI does not support ON_CHANGE events for LACP paths, and SAMPLING can fatally fail if an
	// entry doesn't yet exist (i.e. we call this too quickly after sending a config). So to prevent
	// flakes we run this check twice in a row.
	if lastVal, matched := gnmi.Watch(t, dut, gnmi.OC().Interface(pcName).Aggregation().Member().State(), timeout, predicate).Await(t); !matched {
		log.Warningf("Failed first membership check: %v", lastVal)
		if lastVal, again := gnmi.Watch(t, dut, gnmi.OC().Interface(pcName).Aggregation().Member().State(), timeout, predicate).Await(t); !again {
			return errors.Errorf("member state does not match %v:%v", members, lastVal)
		}
	}
	return nil
}

// Translates an openconfig ETHERNET_SPEED into Mbps which can be used to verify a LAG's speed.
func ethernetPortSpeedToMbps(speed oc.E_IfEthernet_ETHERNET_SPEED) (uint32, error) {
	// Returns bits/sec.
	bps, err := testhelper.EthernetSpeedToUint64(speed)
	if err != nil {
		return 0, err
	}
	return uint32(bps / 1_000_000), nil
}

// Fetches the configured PortSpeed for a list of ports, and aggregates the values together. Can be
// be used to verify a PortChannel speed matches the total of all its member ports.
func aggregatedPortSpeed(t *testing.T, dut *ondatra.DUTDevice, ports []string) (uint32, error) {
	lagSpeed := uint32(0)

	for _, port := range ports {
		portSpeed, err := ethernetPortSpeedToMbps(gnmi.Get(t, dut, gnmi.OC().Interface(port).Ethernet().PortSpeed().Config()))
		if err != nil {
			return 0, errors.Wrapf(err, "could not get port speed for %s", port)
		}
		lagSpeed += portSpeed
	}

	return lagSpeed, nil
}

// Used by go/ondatra to automatically reserve an available testbed.
func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func TestCreatingPortChannel(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("b280a73c-c8e9-411b-b5ef-a22240463377").Teardown(t)

	host := ondatra.DUT(t, "DUT")
	peer := ondatra.DUT(t, "CONTROL")
	t.Logf("Host Device: %v", host.Name())
	t.Logf("Peer Device: %v", peer.Name())

	// Find a set of peer ports between the 2 switches.
	peerPorts, err := testhelper.PeerPortGroupWithNumMembers(t, host, peer, 2)
	if err != nil {
		t.Fatalf("Failed to get enough peer ports: %v", err)
	}
	t.Logf("Using peer ports: %v", peerPorts)

	// The PortChannel configs will be the same on both the host and peer devices so we can reuse
	// them. Since this is a sanity test to verify PortChannels can be created we manually set most of
	// the configuration variables.
	portChannel := "PortChannel200"
	portChannelID := uint32(2001)
	portChannelDescription := "PortChanne200 used for sanity testing."
	portChannelMinLinks := uint16(2)
	portChannelMtu := uint16(1514)
	lacpInterval := oc.Lacp_LacpPeriodType_FAST
	lacpMode := oc.Lacp_LacpActivityType_ACTIVE
	lacpKey := uint16(85)

	portChannelConfig := testhelper.GeneratePortChannelInterface(portChannel)
	portChannelConfig.Id = &portChannelID
	portChannelConfig.Mtu = &portChannelMtu
	portChannelConfig.Description = &portChannelDescription
	portChannelConfig.Aggregation.MinLinks = &portChannelMinLinks
	portChannelConfigs := map[string]*oc.Interface{portChannel: &portChannelConfig}

	lacpConfig := testhelper.GenerateLACPInterface(portChannel)
	lacpConfig.Interval = lacpInterval

	lacpConfig.LacpMode = lacpMode
	var lacpConfigs oc.Lacp
	lacpConfigs.AppendInterface(&lacpConfig)

	deviceConfig := &oc.Root{
		Interface: portChannelConfigs,
		Lacp:      &lacpConfigs,
	}

	// Push the same device config to both switches under test.
	gnmi.Replace(t, host, gnmi.OC().Config(), deviceConfig)
	testhelper.UpdateLacpKey(t, host, portChannel, lacpKey)
	defer func() {
		if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, host, portChannel); err != nil {
			t.Fatalf("Failed to remove %v:%v: %v", host.Name(), portChannel, err)
		}
	}()
	gnmi.Replace(t, peer, gnmi.OC().Config(), deviceConfig)
	testhelper.UpdateLacpKey(t, peer, portChannel, lacpKey)
	defer func() {
		if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, peer, portChannel); err != nil {
			t.Fatalf("Failed to remove %v:%v: %v", peer.Name(), portChannel, err)
		}
	}()

	// Ethernet ports are added to the PortChannel with its ID. Once this is done we expect the
	// PortChannel to be active. Notice that the LAG member's MTU must match the PortChannel's.
	// Otherwise, the FE will reject the request.
	origMtuHostPort0 := gnmi.Get(t, host, gnmi.OC().Interface(peerPorts[0].Host).Mtu().Config())
	origMtuHostPort1 := gnmi.Get(t, host, gnmi.OC().Interface(peerPorts[1].Host).Mtu().Config())
	defer func() {
		gnmi.Replace(t, host, gnmi.OC().Interface(peerPorts[0].Host).Mtu().Config(), origMtuHostPort0)
		gnmi.Replace(t, host, gnmi.OC().Interface(peerPorts[1].Host).Mtu().Config(), origMtuHostPort1)
	}()
	gnmi.Replace(t, host, gnmi.OC().Interface(peerPorts[0].Host).Mtu().Config(), portChannelMtu)
	gnmi.Replace(t, host, gnmi.OC().Interface(peerPorts[1].Host).Mtu().Config(), portChannelMtu)
	testhelper.AssignPortsToAggregateID(t, host, portChannel, peerPorts[0].Host, peerPorts[1].Host)

	origMtuPeerPort0 := gnmi.Get(t, peer, gnmi.OC().Interface(peerPorts[0].Peer).Mtu().Config())
	origMtuPeerPort1 := gnmi.Get(t, peer, gnmi.OC().Interface(peerPorts[1].Peer).Mtu().Config())
	defer func() {
		gnmi.Replace(t, peer, gnmi.OC().Interface(peerPorts[0].Peer).Mtu().Config(), origMtuPeerPort0)
		gnmi.Replace(t, peer, gnmi.OC().Interface(peerPorts[1].Peer).Mtu().Config(), origMtuPeerPort1)
	}()
	gnmi.Replace(t, peer, gnmi.OC().Interface(peerPorts[0].Peer).Mtu().Config(), portChannelMtu)
	gnmi.Replace(t, peer, gnmi.OC().Interface(peerPorts[1].Peer).Mtu().Config(), portChannelMtu)
	testhelper.AssignPortsToAggregateID(t, peer, portChannel, peerPorts[0].Peer, peerPorts[1].Peer)

	// Verify that the Ethernet interfaces are enabled, and assigned to the correct PortChannel.
	gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[0].Host).Enabled().State(), defaultGNMIWait, true)
	gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[0].Host).Ethernet().AggregateId().State(), defaultGNMIWait, portChannel)
	gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[1].Host).Enabled().State(), defaultGNMIWait, true)
	gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[1].Host).Ethernet().AggregateId().State(), defaultGNMIWait, portChannel)

	// Verify the PortChannel interface state.
	gnmi.Await(t, host, gnmi.OC().Interface(portChannel).Enabled().State(), defaultGNMIWait, true)
	gnmi.Await(t, host, gnmi.OC().Interface(portChannel).AdminStatus().State(), defaultGNMIWait, oc.Interface_AdminStatus_UP)
	gnmi.Await(t, host, gnmi.OC().Interface(portChannel).OperStatus().State(), defaultGNMIWait, oc.Interface_OperStatus_UP)
	gnmi.Await(t, host, gnmi.OC().Interface(portChannel).Type().State(), defaultGNMIWait, oc.IETFInterfaces_InterfaceType_ieee8023adLag)
	gnmi.Await(t, host, gnmi.OC().Interface(portChannel).Id().State(), defaultGNMIWait, portChannelID)
	gnmi.Await(t, host, gnmi.OC().Interface(portChannel).Description().State(), defaultGNMIWait, portChannelDescription)
	gnmi.Await(t, host, gnmi.OC().Interface(portChannel).Mtu().State(), defaultGNMIWait, portChannelMtu)
	expectedHostPorts := []string{peerPorts[0].Host, peerPorts[1].Host}
	if err := comparePortChannelMemberList(t, defaultGNMIWait, host, portChannel, expectedHostPorts); err != nil {
		t.Errorf("PortChannel member list is invalid: %v", err)
	}
	// expectedLagSpeed, err := aggregatedPortSpeed(t, host, expectedHostPorts)
	// if err != nil {
	// 	t.Fatalf("Could not get expected LAG speed: %v", err)
	// }

	// TODO: enable after the bug is fixed.
	// Monitoring tools will SAMPLE data from /interfaces/interface[name=<trunk>]/aggregation/state/,
	// and the gNMI FE does not support ON_CHANGE in this case. So we update the subscription mode.
	//gnmi.Await(t, host.GNMIOpts().WithYGNMIOpts(ygnmi.WithSubscriptionMode(gpb.SubscriptionMode_SAMPLE)), gnmi.OC().Interface(portChannel).Aggregation().LagSpeed().State(), defaultGNMIWait, expectedLagSpeed)
	gnmi.Await(t, host.GNMIOpts().WithYGNMIOpts(ygnmi.WithSubscriptionMode(gpb.SubscriptionMode_SAMPLE)), gnmi.OC().Interface(portChannel).Aggregation().MinLinks().State(), defaultGNMIWait, portChannelMinLinks)
	gnmi.Await(t, host.GNMIOpts().WithYGNMIOpts(ygnmi.WithSubscriptionMode(gpb.SubscriptionMode_SAMPLE)), gnmi.OC().Interface(portChannel).Aggregation().LagType().State(), defaultGNMIWait, oc.IfAggregate_AggregationType_LACP)

	// Verify the LACP settings for the PortChannel.
	gnmi.Await(t, host, gnmi.OC().Lacp().Interface(portChannel).Interval().State(), defaultGNMIWait, lacpInterval)
	gnmi.Await(t, host, gnmi.OC().Lacp().Interface(portChannel).LacpMode().State(), defaultGNMIWait, lacpMode)
	testhelper.AwaitLacpKey(t, host, portChannel, defaultGNMIWait, lacpKey)

	// We don't explicitly configure the LACP system MAC or priority. Therefore, the MAC should match
	// whatever the ethernet ports were configured to, and the priority will default to 0xFFFF.
	expectedSystemMac := gnmi.Get(t, host, gnmi.OC().Interface(peerPorts[0].Host).Ethernet().MacAddress().State())
	gnmi.Await(t, host, gnmi.OC().Lacp().Interface(portChannel).SystemIdMac().State(), defaultGNMIWait, expectedSystemMac)
	gnmi.Await(t, host, gnmi.OC().Lacp().Interface(portChannel).SystemPriority().State(), defaultGNMIWait, 0xFFFF)

	// Verify the LACP settings for each member of the PortChannel.
	if err := verifyInSyncState(t, host, portChannel, peerPorts[0].Host); err != nil {
		t.Errorf("LACP state is not in-sync: %v", err)
	}
	gnmi.Await(t, host, gnmi.OC().Lacp().Interface(portChannel).Member(peerPorts[0].Host).SystemId().State(), defaultGNMIWait, expectedSystemMac)
	gnmi.Await(t, host, gnmi.OC().Lacp().Interface(portChannel).Member(peerPorts[0].Host).OperKey().State(), defaultGNMIWait, lacpKey)
	gnmi.Await(t, peer, gnmi.OC().Lacp().Interface(portChannel).Member(peerPorts[0].Peer).PartnerId().State(), defaultGNMIWait, expectedSystemMac)
	gnmi.Await(t, peer, gnmi.OC().Lacp().Interface(portChannel).Member(peerPorts[0].Peer).PartnerKey().State(), defaultGNMIWait, lacpKey)
}

func TestAddingInterfaceToAnExistingPortChannel(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("cda6bc3d-9bfa-44f2-8851-53d42ab2c5bb").Teardown(t)

        host := ondatra.DUT(t, "DUT")
        peer := ondatra.DUT(t, "CONTROL")
        t.Logf("Host Device: %v", host.Name())
        t.Logf("Peer Device: %v", peer.Name())

        // Find a set of peer ports between the 2 switches.
        peerPorts, err := testhelper.PeerPortGroupWithNumMembers(t, host, peer, 2)
        if err != nil {
                t.Fatalf("Failed to get enough peer ports: %v", err)
        }
        t.Logf("Using peer ports: %v", peerPorts)

        // We bring up one PortChannel on both the host and peer device so we can reuse the same device
        // configuration on both without issue.
        portChannel := "PortChannel200"
        portChannelConfig := testhelper.GeneratePortChannelInterface(portChannel)
        portChannelConfigs := map[string]*oc.Interface{portChannel: &portChannelConfig}

        lacpConfig := testhelper.GenerateLACPInterface(portChannel)
        var lacpConfigs oc.Lacp
        lacpConfigs.AppendInterface(&lacpConfig)

        deviceConfig := &oc.Root{
                Interface: portChannelConfigs,
                Lacp:      &lacpConfigs,
        }

        // Push the PortChannel configs and clean them up after the test finishes so they won't affect
        // future tests
        gnmi.Replace(t, host, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, host, portChannel); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", host.Name(), portChannel, err)
                }
        }()
        gnmi.Replace(t, peer, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, peer, portChannel); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", peer.Name(), portChannel, err)
                }
        }()

        // Assign 1 port to each PortChannel so the interfaces become active.
        testhelper.AssignPortsToAggregateID(t, host, portChannel, peerPorts[0].Host)
        testhelper.AssignPortsToAggregateID(t, peer, portChannel, peerPorts[0].Peer)

        // Verify that the Ethernet and PortChannel interfaces are enabled, and that the correct member
        // port is assigned.
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[0].Host).Enabled().State(), defaultGNMIWait, true)
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[0].Host).Ethernet().AggregateId().State(), defaultGNMIWait, portChannel)
        gnmi.Await(t, host, gnmi.OC().Interface(portChannel).Enabled().State(), defaultGNMIWait, true)
        if err := comparePortChannelMemberList(t, defaultGNMIWait, host, portChannel, []string{peerPorts[0].Host}); err != nil {
                t.Errorf("PortChannel member list is invalid: %v", err)
        }

        // Assign additional ports to each PortChannel.
        testhelper.AssignPortsToAggregateID(t, host, portChannel, peerPorts[1].Host)
        testhelper.AssignPortsToAggregateID(t, peer, portChannel, peerPorts[1].Peer)

        // Verify that the new Ethernet interface is enabled, and the PortChannel has the correct member
        // ports assigned.
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[0].Host).Enabled().State(), defaultGNMIWait, true)
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[0].Host).Ethernet().AggregateId().State(), defaultGNMIWait, portChannel)
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[1].Host).Enabled().State(), defaultGNMIWait, true)
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[1].Host).Ethernet().AggregateId().State(), defaultGNMIWait, portChannel)
        gnmi.Await(t, host, gnmi.OC().Interface(portChannel).Enabled().State(), defaultGNMIWait, true)
        if err := comparePortChannelMemberList(t, defaultGNMIWait, host, portChannel, []string{peerPorts[0].Host, peerPorts[1].Host}); err != nil {
                t.Errorf("%s member list is invalid: %v", portChannel, err)
        }
}

func TestRemoveInterfaceFromAnExistingPortChannel(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("7e4936d3-2615-40b4-9cc0-e648c301f5df").Teardown(t)

        host := ondatra.DUT(t, "DUT")
        peer := ondatra.DUT(t, "CONTROL")
        t.Logf("Host Device: %v", host.Name())
        t.Logf("Peer Device: %v", peer.Name())

        // Find a set of peer ports between the 2 switches.
        peerPorts, err := testhelper.PeerPortGroupWithNumMembers(t, host, peer, 2)
        if err != nil {
                t.Fatalf("Failed to get enough peer ports: %v", err)
        }
        t.Logf("Using peer ports: %v", peerPorts)

        // We bring up one PortChannel on both the host and peer device so we can reuse the same device
        // configuration on both without issue.
        portChannel := "PortChannel200"
        portChannelConfig := testhelper.GeneratePortChannelInterface(portChannel)
        portChannelConfigs := map[string]*oc.Interface{portChannel: &portChannelConfig}

        var lacpConfigs oc.Lacp
        portChannelLACPConfig := testhelper.GenerateLACPInterface(portChannel)
        lacpConfigs.AppendInterface(&portChannelLACPConfig)

        deviceConfig := &oc.Root{
                Interface: portChannelConfigs,
                Lacp:      &lacpConfigs,
        }

        // Push the PortChannel configs and clean them up after the test finishes so they won't affect
        // future tests.
        gnmi.Replace(t, host, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, host, portChannel); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", host.Name(), portChannel, err)
                }
        }()
        gnmi.Replace(t, peer, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, peer, portChannel); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", peer.Name(), portChannel, err)
                }
        }()

        // Assign both member ports to each PortChannel, and verify their membership before trying to
        // remove one.
        testhelper.AssignPortsToAggregateID(t, host, portChannel, peerPorts[0].Host, peerPorts[1].Host)
        testhelper.AssignPortsToAggregateID(t, peer, portChannel, peerPorts[0].Peer, peerPorts[1].Peer)
        if err := comparePortChannelMemberList(t, defaultGNMIWait, host, portChannel, []string{peerPorts[0].Host, peerPorts[1].Host}); err != nil {
                t.Errorf("PortChannel member list is invalid: %v", err)
        }

        // Remove a port from the PortChannel and verify it was removed from the member list.
        gnmi.Delete(t, host, gnmi.OC().Interface(peerPorts[1].Host).Ethernet().AggregateId().Config())
        gnmi.Delete(t, peer, gnmi.OC().Interface(peerPorts[1].Peer).Ethernet().AggregateId().Config())
        if err := comparePortChannelMemberList(t, defaultGNMIWait, host, portChannel, []string{peerPorts[0].Host}); err != nil {
                t.Errorf("PortChannel member list is invalid: %v", err)
        }
}

func TestLacpConfiguredOnOnlyOneSwitch(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("71fb9896-993a-4a17-ab47-07b52cc184ee").Teardown(t)

        host := ondatra.DUT(t, "DUT")
        peer := ondatra.DUT(t, "CONTROL")
        t.Logf("Host Device: %v", host.Name())
        t.Logf("Peer Device: %v", peer.Name())

        // Find a set of peer ports between the 2 switches.
        peerPorts, err := testhelper.PeerPortGroupWithNumMembers(t, host, peer, 2)
        if err != nil {
                t.Fatalf("Failed to get enough peer ports: %v", err)
        }
        t.Logf("Using peer ports: %v", peerPorts)

        // We bring up the PortChannel on just the host.
        portChannel := "PortChannel200"
        portChannelConfig := testhelper.GeneratePortChannelInterface(portChannel)
        portChannelConfigs := map[string]*oc.Interface{portChannel: &portChannelConfig}

        lacpConfig := testhelper.GenerateLACPInterface(portChannel)
        var lacpConfigs oc.Lacp
        lacpConfigs.AppendInterface(&lacpConfig)

        deviceConfig := &oc.Root{
                Interface: portChannelConfigs,
                Lacp:      &lacpConfigs,
        }
        gnmi.Replace(t, host, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, host, portChannel); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", host.Name(), portChannel, err)
                }
        }()

        // Only assign the host port to a PortChannel.
        testhelper.AssignPortsToAggregateID(t, host, portChannel, peerPorts[0].Host, peerPorts[1].Host)

        // Ensure ports are enabled before trying to verify state.
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[0].Host).Enabled().State(), defaultGNMIWait, true)
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[1].Host).Enabled().State(), defaultGNMIWait, true)

        if err := verifyBlockingState(t, host, portChannel, peerPorts[0].Host); err != nil {
                t.Errorf("LACP state is not blocking: %v", err)
        }
        if err := verifyBlockingState(t, host, portChannel, peerPorts[1].Host); err != nil {
                t.Errorf("LACP state is not blocking: %v", err)
        }
}

func TestMembersArePartiallyConfigured(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("42eea9f9-043c-45c4-95fd-5c1e00fef959").Teardown(t)

        host := ondatra.DUT(t, "DUT")
        peer := ondatra.DUT(t, "CONTROL")
        t.Logf("Host Device: %v", host.Name())
        t.Logf("Peer Device: %v", peer.Name())

        // Find a set of peer ports between the 2 switches.
        peerPorts, err := testhelper.PeerPortGroupWithNumMembers(t, host, peer, 2)
        if err != nil {
                t.Fatalf("Failed to get enough peer ports: %v", err)
        }
        t.Logf("Using peer ports: %v", peerPorts)

        // We bring up one PortChannel on both the host and peer device so we can reuse the same device
        // configuration on both without issue.
        portChannel := "PortChannel200"
        portChannelConfig := testhelper.GeneratePortChannelInterface(portChannel)
        portChannelConfigs := map[string]*oc.Interface{portChannel: &portChannelConfig}

        lacpConfig := testhelper.GenerateLACPInterface(portChannel)
        var lacpConfigs oc.Lacp
        lacpConfigs.AppendInterface(&lacpConfig)

        deviceConfig := &oc.Root{
                Interface: portChannelConfigs,
                Lacp:      &lacpConfigs,
        }

        // Push the PortChannel configs and clean them up after the test finishes so they won't affect
        // future tests
        gnmi.Replace(t, host, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, host, portChannel); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", host.Name(), portChannel, err)
                }
        }()
        gnmi.Replace(t, peer, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, peer, portChannel); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", peer.Name(), portChannel, err)
                }
        }()

        // On the host assign both ports to the PortChannel, but on the peer only assign 1.
        testhelper.AssignPortsToAggregateID(t, host, portChannel, peerPorts[0].Host, peerPorts[1].Host)
        testhelper.AssignPortsToAggregateID(t, peer, portChannel, peerPorts[0].Peer)

        // Ensure ports are enabled before trying to verify state.
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[0].Host).Enabled().State(), defaultGNMIWait, true)
        gnmi.Await(t, host, gnmi.OC().Interface(peerPorts[1].Host).Enabled().State(), defaultGNMIWait, true)
        gnmi.Await(t, peer, gnmi.OC().Interface(peerPorts[0].Peer).Enabled().State(), defaultGNMIWait, true)

        if err := verifyInSyncState(t, host, portChannel, peerPorts[0].Host); err != nil {
                t.Errorf("LACP state is not in-sync: %v", err)
        }
        if err := verifyInSyncState(t, peer, portChannel, peerPorts[0].Peer); err != nil {
                t.Errorf("LACP state is not in-sync: %v", err)
        }
        if err := verifyBlockingState(t, host, portChannel, peerPorts[1].Host); err != nil {
                t.Errorf("LACP state is not blocking: %v", err)
        }
}

func TestPortDownEvent(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("8b585121-80c1-4ca1-9847-5433ded2ebe6").Teardown(t)

        host := ondatra.DUT(t, "DUT")
        peer := ondatra.DUT(t, "CONTROL")
        t.Logf("Host Device: %v", host.Name())
        t.Logf("Peer Device: %v", peer.Name())

        // Find a set of peer ports between the 2 switches.
        peerPorts, err := testhelper.PeerPortGroupWithNumMembers(t, host, peer, 2)
        if err != nil {
                t.Fatalf("Failed to get enough peer ports: %v", err)
        }
        t.Logf("Using peer ports: %v", peerPorts)

        // The same PortChannel settings will be used on the host and peer devices.
        portChannel1 := "PortChannel200"
        portChannelConfig := testhelper.GeneratePortChannelInterface(portChannel1)
        portChannelConfigs := map[string]*oc.Interface{portChannel1: &portChannelConfig}

        var lacpConfigs oc.Lacp
        lacpConfig := testhelper.GenerateLACPInterface(portChannel1)
        lacpConfigs.AppendInterface(&lacpConfig)

        deviceConfig := &oc.Root{
                Interface: portChannelConfigs,
                Lacp:      &lacpConfigs,
        }
        gnmi.Replace(t, host, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, host, portChannel1); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", host.Name(), portChannel1, err)
                }
        }()
        gnmi.Replace(t, peer, gnmi.OC().Config(), deviceConfig)
        defer func() {
                if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, peer, portChannel1); err != nil {
                        t.Fatalf("Failed to remove %v:%v: %v", peer.Name(), portChannel1, err)
                }
        }()

        // Assign the port to each PortChannel and wait for the links to become active.
        testhelper.AssignPortsToAggregateID(t, host, portChannel1, peerPorts[0].Host, peerPorts[1].Host)
        testhelper.AssignPortsToAggregateID(t, peer, portChannel1, peerPorts[0].Peer, peerPorts[1].Peer)
        gnmi.Await(t, host, gnmi.OC().Interface(portChannel1).Enabled().State(), defaultGNMIWait, true)
        gnmi.Await(t, peer, gnmi.OC().Interface(portChannel1).Enabled().State(), defaultGNMIWait, true)

        // Bring the port down on the peer side.
        gnmi.Replace(t, peer, gnmi.OC().Interface(peerPorts[0].Peer).Enabled().Config(), false)
        defer func() {
                gnmi.Replace(t, peer, gnmi.OC().Interface(peerPorts[0].Peer).Enabled().Config(), true)
        }()

        // Wait for the port to go down on the peer then verify the host side is in a blocking state.
        gnmi.Await(t, peer, gnmi.OC().Interface(peerPorts[0].Peer).Enabled().State(), defaultGNMIWait, false)
        if err := verifyBlockingState(t, host, portChannel1, peerPorts[0].Host); err != nil {
                t.Errorf("LACP state is not blocking: %v", err)
        }
}

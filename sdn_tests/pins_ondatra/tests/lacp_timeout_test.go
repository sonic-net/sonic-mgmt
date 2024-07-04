package lacp_timeout_test

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"github.com/pkg/errors"
)

// gNMI can cache local state for up to 10 seconds. We therefore set our timeout to a little longer
// to handle any edge cases when verifying state.
const defaultGNMIWait = 15 * time.Second

// Convert LACP period types to strings for use in parameterized test names. The output should
// follow CamelCase styles.
func lacpPeriodTypeToString(period oc.E_Lacp_LacpPeriodType) string {
	if period == oc.Lacp_LacpPeriodType_FAST {
		return "Fast"
	} else if period == oc.Lacp_LacpPeriodType_SLOW {
		return "Slow"
	}
	return "Unknown"
}

// Convert LACP activity types to strings for use  in parameterized test names. The output should
// follow CamelCase styles.
func lacpActivityTypeToString(activity oc.E_Lacp_LacpActivityType) string {
	if activity == oc.Lacp_LacpActivityType_ACTIVE {
		return "Active"
	} else if activity == oc.Lacp_LacpActivityType_PASSIVE {
		return "Passive"
	}
	return "Unknown"
}

// Check if the number of packets is within an acceptable range for 1 minute given the LACP Interval.
func acceptableLACPDUPacketCountForOneMinute(period oc.E_Lacp_LacpPeriodType, count uint64) error {
	switch period {
	case oc.Lacp_LacpPeriodType_FAST:
		// When the period is FAST we expect around 1 packet per-second. So ~60 packets.
		if count < 55 || count > 65 {
			return errors.Errorf("outside range [55, 65]: %v.", count)
		}
	case oc.Lacp_LacpPeriodType_SLOW:
		// When the period is SLOW we expect around 1 packet every 30 seconds. So ~2 packets.
		if count < 1 || count > 5 {
			return errors.Errorf("outside range [1, 5]: %v.", count)
		}
	default:
		return errors.Errorf("unhandled period type: %v", period)
	}

	return nil
}

// Verifies the LACP timeout pings are working as expected. Pings can be sent either once every
// second (i.e. FAST), or once every 30 seconds (i.e. SLOW). This test allows for some variability
// in the exact number of pings sent and received, but will fail if the number isn't roughly what we
// expect based on the period type.
func verifyLACPTimeout(t *testing.T, hostActivity oc.E_Lacp_LacpActivityType, hostPeriod oc.E_Lacp_LacpPeriodType, peerActivity oc.E_Lacp_LacpActivityType, peerPeriod oc.E_Lacp_LacpPeriodType) error {
	host := ondatra.DUT(t, "DUT")
	peer := ondatra.DUT(t, "CONTROL")
	t.Logf("Host Device: %v", host.Name())
	t.Logf("Peer Device: %v", peer.Name())

	// Find a set of peer ports between the 2 switches. Notice this test uses multiple port to ensure
	// the correct number of LACPDU packets are being sent per member.
	peerPorts, err := testhelper.PeerPortGroupWithNumMembers(t, host, peer, 4)
	if err != nil {
		return err
	}
	t.Logf("Using peer ports: %v", peerPorts)

	// The interface config for PortChannels will be the same on both switches.
	portChannel := "PortChannel200"
	portChannelConfig := testhelper.GeneratePortChannelInterface(portChannel)
	portChannelConfigs := map[string]*oc.Interface{portChannel: &portChannelConfig}

	// Configure the host side LACP settings.
	hostLACPConfig := testhelper.GenerateLACPInterface(portChannel)
	hostLACPConfig.LacpMode = hostActivity
	hostLACPConfig.Interval = hostPeriod
	var hostLACPConfigs oc.Lacp
	hostLACPConfigs.AppendInterface(&hostLACPConfig)
	hostDeviceConfig := &oc.Root{
		Interface: portChannelConfigs,
		Lacp:      &hostLACPConfigs,
	}
	gnmi.Replace(t, host, gnmi.OC().Config(), hostDeviceConfig)
	defer func() {
		if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, host, portChannel); err != nil {
			t.Fatalf("Failed to remove %v:%v: %v", host.Name(), portChannel, err)
		}
	}()

	// Configure the peer side LACP settings.
	peerLACPConfig := testhelper.GenerateLACPInterface(portChannel)
	peerLACPConfig.LacpMode = peerActivity
	peerLACPConfig.Interval = peerPeriod
	var peerLACPConfigs oc.Lacp
	peerLACPConfigs.AppendInterface(&peerLACPConfig)
	peerDeviceConfig := &oc.Root{
		Interface: portChannelConfigs,
		Lacp:      &peerLACPConfigs,
	}
	gnmi.Replace(t, peer, gnmi.OC().Config(), peerDeviceConfig)
	defer func() {
		if err := testhelper.RemovePortChannelFromDevice(t, defaultGNMIWait, peer, portChannel); err != nil {
			t.Fatalf("Failed to remove %v:%v: %v", peer.Name(), portChannel, err)
		}
	}()

	// Assign all ethernet ports to the port channels on each switch so we will be getting multiple
	// LACPDU packets in flight.
	testhelper.AssignPortsToAggregateID(t, host, portChannel, peerPorts[0].Host, peerPorts[1].Host, peerPorts[2].Host, peerPorts[3].Host)
	testhelper.AssignPortsToAggregateID(t, peer, portChannel, peerPorts[0].Peer, peerPorts[1].Peer, peerPorts[2].Peer, peerPorts[3].Peer)

	// Wait for the PortChannel to become active on each device. Then because LACPDU packets are used
	// to notify peers about any state changes we sleep for a few seconds to give things time to
	// converge.
	gnmi.Await(t, host, gnmi.OC().Interface(portChannel).Enabled().State(), defaultGNMIWait, true)
	gnmi.Await(t, peer, gnmi.OC().Interface(portChannel).Enabled().State(), defaultGNMIWait, true)
	time.Sleep(3 * time.Second)

	// Choose a random port to test, and get the LACPDU count.
	peerportslen := len(peerPorts)
	max := big.NewInt(int64(peerportslen))
        randomIndex, _ := rand.Int(rand.Reader, max)
        port_64 := randomIndex.Int64()
	port := int(port_64)
	hostBefore := gnmi.Get(t, host, gnmi.OC().Lacp().Interface(portChannel).Member(peerPorts[port].Host).Counters().State())
	peerBefore := gnmi.Get(t, peer, gnmi.OC().Lacp().Interface(portChannel).Member(peerPorts[port].Peer).Counters().State())

	// Then sleep for a minute and get the count again.
	time.Sleep(time.Minute)
	hostAfter := gnmi.Get(t, host, gnmi.OC().Lacp().Interface(portChannel).Member(peerPorts[port].Host).Counters().State())
	peerAfter := gnmi.Get(t, peer, gnmi.OC().Lacp().Interface(portChannel).Member(peerPorts[port].Peer).Counters().State())

	// Finally, verify that the total number of LACPDU packets is acceptable for that 1 minute range.
	hostCount := hostAfter.GetLacpInPkts() - hostBefore.GetLacpInPkts()
	if err := acceptableLACPDUPacketCountForOneMinute(hostPeriod, hostCount); err != nil {
		t.Errorf("Host LACPDU count is unacceptable for %v:%v: %v", host.Name(), peerPorts[port].Host, err)
	}
	peerCount := peerAfter.GetLacpInPkts() - peerBefore.GetLacpInPkts()
	if err := acceptableLACPDUPacketCountForOneMinute(peerPeriod, peerCount); err != nil {
		t.Errorf("Peer LACPDU count is unacceptable for %v:%v: %v", peer.Name(), peerPorts[port].Peer, err)
	}

	// Also do a sanity check that gNMI is reporting the LacpOutPkts. Assuming we get here without
	// failure then we know LACP is sending the packets out so we don't really care what this value is
	// so long at it's >0.
	if outPackets := hostAfter.GetLacpOutPkts(); outPackets == 0 {
		t.Errorf("Host is not reporting any LACPDU output packets: got=%v", outPackets)
	}

	return nil
}

func TestLACPTimeouts(t *testing.T) {
	// Testing LACPDU behavior with different timeout & activity settings (b4feaa45) and
	// LACPDU counters (e9805bdf).
	defer testhelper.NewTearDownOptions(t).WithID("b4feaa45-6088-4fa5-9f62-8adbc933c693").WithID("e9805bdf-1349-4fec-940b-1c710dc0c849").Teardown(t)

	tests := []struct {
		hostActivity oc.E_Lacp_LacpActivityType
		hostPeriod   oc.E_Lacp_LacpPeriodType
		peerActivity oc.E_Lacp_LacpActivityType
		peerPeriod   oc.E_Lacp_LacpPeriodType
	}{
		{oc.Lacp_LacpActivityType_ACTIVE, oc.Lacp_LacpPeriodType_FAST, oc.Lacp_LacpActivityType_ACTIVE, oc.Lacp_LacpPeriodType_FAST},
		{oc.Lacp_LacpActivityType_ACTIVE, oc.Lacp_LacpPeriodType_FAST, oc.Lacp_LacpActivityType_ACTIVE, oc.Lacp_LacpPeriodType_SLOW},
		{oc.Lacp_LacpActivityType_ACTIVE, oc.Lacp_LacpPeriodType_FAST, oc.Lacp_LacpActivityType_PASSIVE, oc.Lacp_LacpPeriodType_FAST},
		{oc.Lacp_LacpActivityType_ACTIVE, oc.Lacp_LacpPeriodType_FAST, oc.Lacp_LacpActivityType_PASSIVE, oc.Lacp_LacpPeriodType_SLOW},
		{oc.Lacp_LacpActivityType_ACTIVE, oc.Lacp_LacpPeriodType_SLOW, oc.Lacp_LacpActivityType_PASSIVE, oc.Lacp_LacpPeriodType_FAST},
		{oc.Lacp_LacpActivityType_ACTIVE, oc.Lacp_LacpPeriodType_SLOW, oc.Lacp_LacpActivityType_PASSIVE, oc.Lacp_LacpPeriodType_SLOW},
	}

	for _, test := range tests {
		// Pretty print the test name based on the activity & period settings for host and peer switches.
		// The names should look like: ActiveFastWithPassiveSlow, ActiveFastWithActiveSlow, etc.
		hostSettings := lacpActivityTypeToString(test.hostActivity) + lacpPeriodTypeToString(test.hostPeriod)
		peerSettings := lacpActivityTypeToString(test.peerActivity) + lacpPeriodTypeToString(test.peerPeriod)
		name := hostSettings + "With" + peerSettings

		t.Run(name, func(t *testing.T) {
			if got := verifyLACPTimeout(t, test.hostActivity, test.hostPeriod, test.peerActivity, test.peerPeriod); got != nil {
				t.Errorf("LACP timeout test failed: %v", got)
			}
		})
	}
}

// Used by go/ondatra to automatically reserve an available testbed.
func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

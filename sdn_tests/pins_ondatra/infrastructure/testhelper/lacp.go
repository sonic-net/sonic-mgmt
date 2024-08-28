package testhelper

import (
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/pkg/errors"
)

// PeerPorts holds the name of 2 Ethernet interfaces. These interfaces will be on separate machines,
// but connected to each other by a cable.
type PeerPorts struct {
	Host string
	Peer string
}

// PeerPortsBySpeed iterates through all the available Ethernet ports on a host device, and
// determines if they have a matching port on the peer device. All host ports with a valid peer will
// be grouped together based on their speed.
func PeerPortsBySpeed(t *testing.T, host *ondatra.DUTDevice, peer *ondatra.DUTDevice) map[oc.E_IfEthernet_ETHERNET_SPEED][]PeerPorts {
	peerPortsBySpeed := make(map[oc.E_IfEthernet_ETHERNET_SPEED][]PeerPorts)

	for _, hostPort := range testhelperDUTPortsGet(host) {
		peerPort := testhelperDUTPortGet(t, peer, testhelperOndatraPortIDGet(hostPort))

		// Verify the host port is UP. Otherwise, LACPDU packets will never be transmitted.
		if got, want := testhelperIntfOperStatusGet(t, host, testhelperOndatraPortNameGet(hostPort)), oc.Interface_OperStatus_UP; got != want {
			log.Warningf("Port %v:%v oper state will not work for LACP testing: want=%v got=%v", testhelperDUTNameGet(host), testhelperOndatraPortNameGet(hostPort), want, got)
			continue
		}

		// Verify we are not already part of an existing PortChannel since one port cannot belong to
		// multiple PortChannels.
		if got, want := testhelperConfigIntfAggregateIDGet(t, host, testhelperOndatraPortNameGet(hostPort)), ""; got != want {
			log.Warningf("Port %v:%v cannot be used since it is already assigned to a PortChannel: want=%v got=%v", testhelperDUTNameGet(host), testhelperOndatraPortNameGet(hostPort), want, got)
			continue
		}

		// Check that the host port has a valid peer port.
		if peerPort == nil {
			log.Warningf("Port %v:%v does not have a peer on %v.", testhelperDUTNameGet(host), testhelperOndatraPortNameGet(hostPort), testhelperDUTNameGet(peer))
			continue
		}

		log.Infof("Found peer ports: %v:%v and %v:%v", testhelperDUTNameGet(host), testhelperOndatraPortNameGet(hostPort), testhelperDUTNameGet(peer), testhelperOndatraPortNameGet(peerPort))
		portSpeed := testhelperConfigPortSpeedGet(t, host, testhelperOndatraPortNameGet(hostPort))
		peerPortsBySpeed[portSpeed] = append(peerPortsBySpeed[portSpeed], PeerPorts{testhelperOndatraPortNameGet(hostPort), testhelperOndatraPortNameGet(peerPort)})
	}

	return peerPortsBySpeed
}

// PeerPortGroupWithNumMembers returns a list of PeerPorts of size `numMembers`.
func PeerPortGroupWithNumMembers(t *testing.T, host *ondatra.DUTDevice, peer *ondatra.DUTDevice, numMembers int) ([]PeerPorts, error) {
	// GPINs requires that all members of a LACP LAG have the same speed. So we first group all the
	// ports based on their configured speed.
	peerPortsBySpeed := PeerPortsBySpeed(t, host, peer)

	// Then we search through the port speed gropus for one that has enough members to match the users
	// requested amount.
	for _, ports := range peerPortsBySpeed {
		if len(ports) >= numMembers {
			// Only return enough members to match the users request.
			return ports[0:numMembers], nil
		}
	}
	return nil, errors.Errorf("cannot make group of %v member ports with the same speed from %v.", numMembers, peerPortsBySpeed)
}

// GeneratePortChannelInterface will return a minimal PortChannel interface that tests can extend as needed.
func GeneratePortChannelInterface(portChannelName string) oc.Interface {
	enabled := true

	description := "PortChannel: " + portChannelName + " used for testing gNMI configuration."
	minLinks := uint16(1)

	// Unsupported fields: Id, Aggregation/LagType
	return oc.Interface{
		Name:        &portChannelName,
		Enabled:     &enabled,
		Type:        oc.IETFInterfaces_InterfaceType_ieee8023adLag,
		Description: &description,
		Aggregation: &oc.Interface_Aggregation{
			LagType:  oc.IfAggregate_AggregationType_LACP,
			MinLinks: &minLinks,
		},
	}
}

// GenerateLACPInterface creates a minimal LACP interface that tests can then extend as needed.
func GenerateLACPInterface(pcName string) oc.Lacp_Interface {

	return oc.Lacp_Interface{
		Name:     &pcName,
		Interval: oc.Lacp_LacpPeriodType_FAST,
		LacpMode: oc.Lacp_LacpActivityType_ACTIVE,
	}
}

// RemovePortChannelFromDevice will cleanup all configs relating to a PortChannel on a given switch.
// It will also verify that the state has been updated before returning. If the state fails to
// converge then an error will be returned.
func RemovePortChannelFromDevice(t *testing.T, timeout time.Duration, dut *ondatra.DUTDevice, portChannelName string) error {
	// We only need to delete the PortChannel interface and gNMI should take care of all the other
	// configs relating to the PortChannel.
	testhelperIntfDelete(t, dut, portChannelName)

	stopTime := time.Now().Add(timeout)
	for time.Now().Before(stopTime) {
		if !testhelperIntfLookup(t, dut, portChannelName).IsPresent() {
			return nil
		}
		time.Sleep(time.Second)
	}

	return errors.Errorf("interface still exists after %v", timeout)
}

// AssignPortsToAggregateID will assign the list of ports to the given aggregate ID on a device. The
// aggregate ID should correspond to an existing PortChannel interface or this call will fail.
func AssignPortsToAggregateID(t *testing.T, dut *ondatra.DUTDevice, portChannelName string, portNames ...string) {
	for _, portName := range portNames {
		log.Infof("Assigning %v:%v to %v", testhelperDUTNameGet(dut), portName, portChannelName)
		testhelperIntfAggregateIDReplace(t, dut, portName, portChannelName)
	}
}

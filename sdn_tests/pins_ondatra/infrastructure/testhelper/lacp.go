package testhelper

import (
	"github.com/openconfig/ondatra/gnmi/oc"
)

// PeerPorts holds the name of 2 Ethernet interfaces. These interfaces will be on separate machines,
// but connected to each other by a cable.
type PeerPorts struct {
	Host string
	Peer string
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

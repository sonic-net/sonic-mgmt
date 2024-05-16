package testhelper

// This file provides helper APIs to perform ports related operations.

import (
	"strconv"
	"strings"

	"github.com/openconfig/ondatra/gnmi/oc"
)

type speedEnumInfo struct {
	// Speed value in string format in bits/second.
	speedStr string
	// Speed value in integer format in bits/second.
	speedInt uint64
}

var stringToEnumSpeedMap = map[string]oc.E_IfEthernet_ETHERNET_SPEED{
	"10M":   oc.IfEthernet_ETHERNET_SPEED_SPEED_10MB,
	"100M":  oc.IfEthernet_ETHERNET_SPEED_SPEED_100MB,
	"1G":    oc.IfEthernet_ETHERNET_SPEED_SPEED_1GB,
	"2500M": oc.IfEthernet_ETHERNET_SPEED_SPEED_2500MB,
	"5G":    oc.IfEthernet_ETHERNET_SPEED_SPEED_5GB,
	"10G":   oc.IfEthernet_ETHERNET_SPEED_SPEED_10GB,
	"25G":   oc.IfEthernet_ETHERNET_SPEED_SPEED_25GB,
	"40G":   oc.IfEthernet_ETHERNET_SPEED_SPEED_40GB,
	"50G":   oc.IfEthernet_ETHERNET_SPEED_SPEED_50GB,
	"100G":  oc.IfEthernet_ETHERNET_SPEED_SPEED_100GB,
	"200G":  oc.IfEthernet_ETHERNET_SPEED_SPEED_200GB,
	"400G":  oc.IfEthernet_ETHERNET_SPEED_SPEED_400GB,
	"600G":  oc.IfEthernet_ETHERNET_SPEED_SPEED_600GB,
	"800G":  oc.IfEthernet_ETHERNET_SPEED_SPEED_800GB,
}

var enumToSpeedInfoMap = map[oc.E_IfEthernet_ETHERNET_SPEED]speedEnumInfo{
	oc.IfEthernet_ETHERNET_SPEED_SPEED_10MB:   {"10M", 10_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_100MB:  {"100M", 100_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_1GB:    {"1G", 1_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_2500MB: {"2500M", 2500_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_5GB:    {"5G", 5_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_10GB:   {"10G", 10_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_25GB:   {"25G", 25_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_40GB:   {"40G", 40_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_50GB:   {"50G", 50_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_100GB:  {"100G", 100_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_200GB:  {"200G", 200_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_400GB:  {"400G", 400_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_600GB:  {"600G", 600_000_000_000},
	oc.IfEthernet_ETHERNET_SPEED_SPEED_800GB:  {"800G", 800_000_000_000},
}

// Indices for slot, port and lane number in Ethernet<slot/port/lane> port naming format.
const (
	slotIndex int = iota
	portIndex
	laneIndex
)

// PortProperties contains front panel port information.
type PortProperties struct {
	index                  int
	supportedSpeeds        map[string]map[int][]oc.E_IfEthernet_ETHERNET_SPEED
	defaultBreakoutMode    string
	supportedBreakoutModes map[string][]string
	mediaType              string
}

// RandomPortBreakoutInfo contains information about a randomly picked port on the switch.
type RandomPortBreakoutInfo struct {
	PortName              string // Randomly selected port on switch.
	CurrBreakoutMode      string // Currently configured breakout mode on the port.
	SupportedBreakoutMode string // Supported breakout mode on port different from current breakout mode.
}

// BreakoutType describes the possible types of breakout modes
type BreakoutType int

const (
	// Unset indicates a not set breakout mode to be used where breakout is not applicable.
	Unset BreakoutType = iota
	// Any indicates any breakout modes (mixed as well as non-mixed)
	Any
	// Mixed indicates mixed breakout modes only
	Mixed
	// NonMixed indicates non mixed breakout only
	NonMixed
	// Channelized indicates breakout mode with at least one more port other than parent port.
	// This mode is used to test breakout with subinterface config on child port.
	Channelized
	// SpeedChangeOnly indicates breakout mode that results in a speed change only (no lane change) on requested number of ports.
	SpeedChangeOnly
)

// PortBreakoutInfo contains list of resultant ports for a given breakout mode and physical channels and operational status for each interface.
type PortBreakoutInfo struct {
	PhysicalChannels []uint16
	OperStatus       oc.E_Interface_OperStatus
	PortSpeed        oc.E_IfEthernet_ETHERNET_SPEED
}

// RandomPortWithSupportedBreakoutModesParams contains list of additional parameters for RandomPortWithSupportedBreakoutModes
type RandomPortWithSupportedBreakoutModesParams struct {
	CurrBreakoutType         BreakoutType // mixed/non-mixed/any/channelized
	NewBreakoutType          BreakoutType // mixed/non-mixed/any/channelized
	SpeedChangeOnlyPortCount int          // number of ports that are required to change in speed only on breakout
	PortList                 []string     // List of ports from which a random port can be selected
}

// Uint16ListToString returns comma separate string representation of list of uint16.
func Uint16ListToString(a []uint16) string {
	s := make([]string, len(a))
	for index, value := range a {
		s[index] = strconv.Itoa(int(value))
	}
	return strings.Join(s, ",")
}

func fecMode(portSpeed oc.E_IfEthernet_ETHERNET_SPEED, lanes uint8) oc.E_IfEthernet_INTERFACE_FEC {
	switch portSpeed {
	case oc.IfEthernet_ETHERNET_SPEED_SPEED_400GB:
		return oc.IfEthernet_INTERFACE_FEC_FEC_RS544_2X_INTERLEAVE
	case oc.IfEthernet_ETHERNET_SPEED_SPEED_200GB:
		return oc.IfEthernet_INTERFACE_FEC_FEC_RS544_2X_INTERLEAVE
	case oc.IfEthernet_ETHERNET_SPEED_SPEED_100GB:
		switch lanes {
		case 1, 2:
			return oc.IfEthernet_INTERFACE_FEC_FEC_RS544
		case 4:
			return oc.IfEthernet_INTERFACE_FEC_FEC_RS528
		}
	case oc.IfEthernet_ETHERNET_SPEED_SPEED_50GB:
		switch lanes {
		case 1:
			return oc.IfEthernet_INTERFACE_FEC_FEC_RS544
		case 2:
			return oc.IfEthernet_INTERFACE_FEC_FEC_DISABLED
		}
	}

	return oc.IfEthernet_INTERFACE_FEC_FEC_DISABLED
}

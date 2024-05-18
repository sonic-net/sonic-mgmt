package testhelper

// This file provides helper APIs to perform ports related operations.

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"math"

	log "github.com/golang/glog"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/pkg/errors"
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

// CollateralFlapAllowed indicates if collateral link flap is allowed on the platform, pmd type.
func CollateralFlapAllowed(t *testing.T, dut *ondatra.DUTDevice, pmdType string) (bool, error) {
	info, err := portInfoForDevice(t, dut)
	if err != nil {
		return false, errors.Wrap(err, "failed to fetch platform specific information")
	}
	if pmdProperty, err := info.PMDProperty(PMDType(pmdType)); err == nil {
		return pmdProperty.CollateralFlap, nil
	}

	// Assume collateral flap is not allowed if entry doesn't exist!
	log.Infof("Update collateralFlap map to include PMD type: %v!", pmdType)
	return false, nil
}

// EthernetSpeedToBpsString returns speed in string format in bits/second.
func EthernetSpeedToBpsString(speed oc.E_IfEthernet_ETHERNET_SPEED) (string, error) {
	if _, ok := enumToSpeedInfoMap[speed]; !ok {
		return "", errors.Errorf("invalid speed (%v) found", speed)
	}
	return enumToSpeedInfoMap[speed].speedStr, nil
}

// EthernetSpeedToUint64 returns the speed in uint64 format.
func EthernetSpeedToUint64(speed oc.E_IfEthernet_ETHERNET_SPEED) (uint64, error) {
	if _, ok := enumToSpeedInfoMap[speed]; !ok {
		return 0, errors.Errorf("invalid speed (%v) found", speed)
	}
	return enumToSpeedInfoMap[speed].speedInt, nil
}

// FrontPanelPortToIndexMappingForDevice returns list of front panel port to index mapping.
func FrontPanelPortToIndexMappingForDevice(t *testing.T, dut *ondatra.DUTDevice) (map[string]int, error) {
	info, err := portInfoForDevice(t, dut)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch platform specific information")
	}
	portToIndexMap := make(map[string]int)
	for port, value := range info.PortProperties {
		portToIndexMap[port] = value.Index
	}
	return portToIndexMap, nil
}

// SupportedSpeedsForPort returns list of supported speeds for given interface.
func SupportedSpeedsForPort(t *testing.T, dut *ondatra.DUTDevice, interfaceName string) ([]oc.E_IfEthernet_ETHERNET_SPEED, error) {
	info, err := portInfoForDevice(t, dut)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch platform specific information")
	}
	lanes := len(testhelperIntfPhysicalChannelsGet(t, dut, interfaceName))
	pmd, err := testhelperPortPmdTypeGet(t, dut, interfaceName)
	if err != nil {
		return nil, err
	}
	pmdProperty, err := info.PMDProperty(PMDType(pmd))
	if err != nil {
		return nil, err
	}
	if v := pmdProperty.SupportedSpeeds[Lanes(lanes)]; len(v) != 0 {
		return v, nil
	}
	return nil, errors.Errorf("no supported speeds found for interface %v pmd %v with %v lanes", interfaceName, pmd, lanes)
}

// TransceiverEmpty returns true if the transceiver status is 0, false if the status is 1
func TransceiverEmpty(t *testing.T, d *ondatra.DUTDevice, port string) (bool, error) {
	transceiverNumber, err := TransceiverNumberForPort(t, d, port)
	if err != nil {
		return false, err
	}
	return testhelperTransceiverEmpty(t, d, FrontPanelPortPrefix+strconv.Itoa(transceiverNumber)), nil
}

// MaxLanesPerPort returns the maximum number of ASIC lanes per port on the dut.
func MaxLanesPerPort(t *testing.T, dut *ondatra.DUTDevice) (uint8, error) {
	info, err := portInfoForDevice(t, dut)
	if err != nil {
		return 0, errors.Wrap(err, "failed to fetch platform specific information")
	}
	return uint8(info.MaxLanes), nil
}

func breakoutModeFromGroup(port string, groups *oc.Component_Port_BreakoutMode) (string, error) {
	currentBreakoutMode := ""
	// Use 0 based index to access breakout groups in increasing index order.
	index := uint8(0)
	_, ok := groups.Group[index]
	for ok == true {
		if index > 0 {
			currentBreakoutMode += "+"
		}
		breakoutSpeed := groups.Group[index].GetBreakoutSpeed()
		breakoutSpeedStr, err := EthernetSpeedToBpsString(breakoutSpeed)
		if err != nil {
			return "", err
		}
		currentBreakoutMode += strconv.Itoa(int(groups.Group[index].GetNumBreakouts())) + "x" + breakoutSpeedStr
		index++
		_, ok = groups.Group[index]
	}
	return currentBreakoutMode, nil
}

// CurrentBreakoutModeForPort returns the currently configured breakout mode for given port.
func CurrentBreakoutModeForPort(t *testing.T, dut *ondatra.DUTDevice, port string) (string, error) {
	// Check if requested port is a parent port. Breakout is applicable to parent port only.
	isParent, err := IsParentPort(t, dut, port)
	if err != nil {
		return "", errors.Wrap(err, "IsParentPort() failed")
	}
	if !isParent {
		return "", errors.Errorf("port: %v is not a parent port", port)
	}
	// Get the physical port for given port.
	physicalPort, err := PhysicalPort(t, dut, port)
	if err != nil {
		return "", errors.Errorf("failed to get physical port for interface %v", port)
	}
	// Get breakout group information from component state paths.
	groups := testhelperBreakoutModeGet(t, dut, physicalPort)
	if groups == nil {
		return "", errors.Errorf("failed to get breakout mode for port %v", port)
	}
	return breakoutModeFromGroup(port, groups)
}

// SupportedBreakoutModesForPort returns list of supported breakout modes for given interface.
func SupportedBreakoutModesForPort(t *testing.T, dut *ondatra.DUTDevice, interfaceName string, breakoutType BreakoutType) ([]string, error) {
	info, err := portInfoForDevice(t, dut)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch platform specific information")
	}
	_, ok := info.PortProperties[interfaceName]
	if !ok {
		return nil, errors.Errorf("no entry found for interface %v in front panel port list", interfaceName)
	}

	pmd, err := testhelperPortPmdTypeGet(t, dut, interfaceName)
	if err != nil {
		return nil, err
	}

	// TODO: the function should take port into consideration.
	pmdProperty, err := info.PMDProperty(PMDType(pmd))
	if err != nil {
		return nil, err
	}

	// Return requested type of breakout modes only.
	var supportedBreakoutModesOfBreakoutType []string
	if breakoutType == Mixed {
		for _, mode := range pmdProperty.SupportedBreakoutModes {
			if strings.Contains(mode, "+") {
				supportedBreakoutModesOfBreakoutType = append(supportedBreakoutModesOfBreakoutType, mode)
			}
		}
		//pmdProperty.SupportedBreakoutModes = supportedBreakoutModesOfBreakoutType
	}
	if breakoutType == NonMixed {
		for _, mode := range pmdProperty.SupportedBreakoutModes {
			if !strings.Contains(mode, "+") {
				supportedBreakoutModesOfBreakoutType = append(supportedBreakoutModesOfBreakoutType, mode)
			}
		}
		//pmdProperty.SupportedBreakoutModes = supportedBreakoutModesOfBreakoutType
	}
	if breakoutType == Channelized {
		for _, mode := range pmdProperty.SupportedBreakoutModes {
			values := strings.Split(mode, "x")
			if len(values) < 2 {
				return nil, errors.Errorf("invalid breakout format (%v)", mode)
			}
			numBreakouts, err := strconv.Atoi(values[0])
			if err != nil {
				return nil, errors.Wrapf(err, "error parsing numBreakouts for breakout mode %v", mode)
			}
			if strings.Contains(mode, "+") || numBreakouts > 1 {
				supportedBreakoutModesOfBreakoutType = append(supportedBreakoutModesOfBreakoutType, mode)
			}
		}
		//pmdProperty.SupportedBreakoutModes = supportedBreakoutModesOfBreakoutType
	}
	return supportedBreakoutModesOfBreakoutType, nil
}

// PortMediaType returns the media type of the requested port.
func PortMediaType(t *testing.T, dut *ondatra.DUTDevice, interfaceName string) (string, error) {
	info, err := portInfoForDevice(t, dut)
	if err != nil {
		return "", errors.Wrap(err, "failed to fetch platform specific information")
	}
	port, ok := info.PortProperties[interfaceName]
	if !ok {
		return "", errors.Errorf("no entry found for interface %v in front panel port list", interfaceName)
	}
	return port.MediaType, nil
}

func slotPortLaneForPort(port string) ([]string, error) {
	if !IsFrontPanelPort(port) {
		return nil, errors.Errorf("requested port (%v) is not a front panel port", port)
	}
	slotPortLane := port[len(FrontPanelPortPrefix):]
	values := strings.Split(slotPortLane, "/")
	if len(values) != 3 {
		return nil, errors.Errorf("invalid port name format for port %v", port)
	}
	return values, nil
}

// ExpectedPortInfoForBreakoutMode returns the expected port list, physical channels and port speed for a given breakout mode.
// Eg. Ethernet0 configured to a breakout mode of "2x100G(4) + 1x200G(4)" will return the following:
// Ethernet0:{0,1}, Ethernet2:{2,3}, Ethernet4:{4,5,6,7}
// The number of physical channels per breakout mode is used to compute the offset from the parent port number.
func ExpectedPortInfoForBreakoutMode(t *testing.T, dut *ondatra.DUTDevice, interfaceName string, breakoutMode string) (map[string]*PortBreakoutInfo, error) {
	if len(breakoutMode) == 0 {
		return nil, errors.Errorf("found empty breakout mode")
	}
	// For a mixed breakout mode, get "+" separated breakout groups.
	// Eg. For a mixed breakout mode of "2x100G(4) + 1x200G(4)"; modes = {2x100G(4), 1x200G(4)}
	modes := strings.Split(breakoutMode, "+")
	// Get maximum physical channels in a breakout group which is max lanes per physical port/number of groups in a breakout mode.
	maxLanes, err := MaxLanesPerPort(t, dut)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch max lanes")
	}
	maxChannelsInGroup := int(maxLanes) / len(modes)
	slotPortLane, err := slotPortLaneForPort(interfaceName)
	if err != nil {
		return nil, err
	}
	currLaneNumber, err := strconv.Atoi(slotPortLane[laneIndex])
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert lane number (%v) to int", currLaneNumber)
	}

	// For each breakout group, get numBreakouts and breakoutSpeed. Breakout group is in the format "numBreakouts x breakoutSpeed"
	// Eg. mode = 2x100G
	currPhysicalChannel := 0
	portBreakoutInfo := make(map[string]*PortBreakoutInfo)
	interfaceToPhysicalChannelsMap := make(map[string][]uint16)
	for _, mode := range modes {
		values := strings.Split(mode, "x")
		if len(values) != 2 {
			return nil, errors.Errorf("invalid breakout format (%v)", mode)
		}
		numBreakouts, err := strconv.Atoi(values[0])
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing numBreakouts for breakout mode %v", mode)
		}
		// Extract speed from breakout_speed(num_physical_channels) eg:100G(4)
		speed := strings.Split(values[1], "(")
		breakoutSpeed, ok := stringToEnumSpeedMap[speed[0]]
		if !ok {
			return nil, errors.Errorf("found invalid breakout speed (%v) when parsing breakout mode %v", values[1], mode)
		}
		// For each resulting interface, construct the front panel interface name using offset from the parent port.
		// For a breakout mode of Ethernet0 => 2x100G(4)+1x200G(4), the max channels per group would be 4 (considering 8 max lanes per physical port).
		// Hence, breakout mode 2x100G (numBreakouts=2) would have an offset of 2 and 1x200G(numBreakouts=1) would have an offset of 1
		// leading to interfaces Ethernet0, Ethernet2 for mode 2x100G and Ethernet4 for mode 1x200G.
		for i := 0; i < numBreakouts; i++ {
			port := fmt.Sprintf("%s%s/%s/%d", FrontPanelPortPrefix, slotPortLane[slotIndex], slotPortLane[portIndex], currLaneNumber)
			// Populate expected physical channels for each port.
			// Physical channels are between 0 to 7.
			offset := maxChannelsInGroup / numBreakouts
			for j := currPhysicalChannel; j < offset+currPhysicalChannel; j++ {
				interfaceToPhysicalChannelsMap[port] = append(interfaceToPhysicalChannelsMap[port], uint16(j))
			}
			currPhysicalChannel += offset
			currLaneNumber += offset
			portBreakoutInfo[port] = &PortBreakoutInfo{
				PhysicalChannels: interfaceToPhysicalChannelsMap[port],
				PortSpeed:        breakoutSpeed,
			}
		}
	}
	return portBreakoutInfo, nil
}

func computePortIDForPort(t *testing.T, d *ondatra.DUTDevice, intfName string) (uint32, error) {
	// Try to get currently configured id for the port from the switch.
	var id int
	var laneindexuint32 uint32
	var Id uint32
	id, err := testhelperPortIDGet(t, d, intfName)
	// Generate ID same as that used by controller, if not found on switch.
	if err != nil {
		isParent, err := IsParentPort(t, d, intfName)
		if err != nil {
			return 0, err
		}
		parentPortNumberStr, err := ParentPortNumber(intfName)
		if err != nil {
			return 0, err
		}
                parentPortNumber, err := conversionTouint32(parentPortNumberStr)
		if err != nil {
			return 0, err
		}
		// Port ID is same as port index/parent port number for parent ports.
		if isParent {
			return parentPortNumber, nil
		}
		// Port ID is computed for child ports using
		// (laneIndex*512 + parentPortNumber + 1)
		slotPortLane, err := slotPortLaneForPort(intfName)
		if err != nil {
			return 0, err
		}
		laneIndex, err := strconv.Atoi(slotPortLane[laneIndex])
		if err != nil {
			return 0, err
		}
		laneindexuint32 = uint32(laneIndex*512)
		return (laneindexuint32 + parentPortNumber + 1), nil
	}
	Id = uint32(id)
	return Id, nil
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

func interfaceConfigForPort(t *testing.T, d *ondatra.DUTDevice, intfName string, breakoutSpeed oc.E_IfEthernet_ETHERNET_SPEED, fec oc.E_IfEthernet_INTERFACE_FEC) (*oc.Interface, error) {
	subinterfaceIndex := uint32(0)
	unnumberedEnabled := true
	mtu := uint16(9216)
	enabled := true
	id, err := computePortIDForPort(t, d, intfName)
	if err != nil {
		return nil, err
	}
	interfaceConfig := &oc.Interface{
		Enabled:      &enabled,
		LoopbackMode: oc.Interfaces_LoopbackModeType_NONE,
		Mtu:          &mtu,
		Name:         &intfName,
		Id:           &id,
		Ethernet: &oc.Interface_Ethernet{
			PortSpeed: breakoutSpeed,
			FecMode:   fec,
		},
		Subinterface: map[uint32]*oc.Interface_Subinterface{
			0: {
				Index: &subinterfaceIndex,
				Ipv6: &oc.Interface_Subinterface_Ipv6{
					Unnumbered: &oc.Interface_Subinterface_Ipv6_Unnumbered{
						Enabled: &unnumberedEnabled,
					},
				},
			},
		},
	}
	return interfaceConfig, nil
}

// ConfigFromBreakoutMode returns config with component and interface paths for given breakout mode.
// Breakout mode is in the format "numBreakouts1 x breakoutSpeed1 + numBreakouts2 x breakoutSpeed2 + ...
// Eg: "1x400G", 2x100G(4) + 1x200G(4)"
func ConfigFromBreakoutMode(t *testing.T, dut *ondatra.DUTDevice, breakoutMode, port string) (*oc.Root, error) {
	if len(breakoutMode) == 0 {
		return nil, errors.Errorf("found empty breakout mode")
	}

	// Check if requested port is a parent port. Breakout is applicable to parent port only.
	isParent, err := IsParentPort(t, dut, port)
	if err != nil {
		return nil, errors.Wrap(err, "IsParentPort() failed")
	}
	if !isParent {
		return nil, errors.Errorf("port: %v is not a parent port", port)
	}
	// Get lane number for port.
	slotPortLane, err := slotPortLaneForPort(port)
	if err != nil {
		return nil, err
	}
	currLaneNumber, err := strconv.Atoi(slotPortLane[laneIndex])
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert lane number (%v) to int", currLaneNumber)
	}

	maxLanes, err := MaxLanesPerPort(t, dut)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch max lanes")
	}

	// For a mixed breakout mode, get "+" separated breakout groups.
	// Eg. For a breakout mode of "2x100G(4)+1x200G(4)", modes = {2x100G, 1x200G}
	modes := strings.Split(breakoutMode, "+")
	// Get maximum physical channels in a breakout group which is max lanes per physical port/number of groups in a breakout mode.
	maxChannelsInGroup := maxLanes / uint8(len(modes))
	index := 0
	breakoutGroups := make(map[uint8]*oc.Component_Port_BreakoutMode_Group)
	interfaceConfig := make(map[string]*oc.Interface)

	// For each breakout group, get numBreakouts and breakoutSpeed. Breakout group is in the format "numBreakouts x breakoutSpeed(numPhysicalChannels)"
	// Eg. 2x100G(4)
	for _, mode := range modes {
		values := strings.Split(mode, "x")
		if len(values) != 2 {
			return nil, errors.Errorf("invalid breakout format (%v)", mode)
		}
		numBreakouts, err := portStringToUint8(values[0])
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing numBreakouts for breakout mode %v", mode)
		}
	        u8numBreakouts := numBreakouts
		// Extract speed from breakout_speed(num_physical_channels) eg:100G(4)
		speed := strings.Split(values[1], "(")
		breakoutSpeed, ok := stringToEnumSpeedMap[speed[0]]
		if !ok {
			return nil, errors.Errorf("found invalid breakout speed (%v) when parsing breakout mode %v", values[1], mode)
		}
		// Physical channels per breakout group are equally divided amongst breakouts in the group.
		numPhysicalChannels := maxChannelsInGroup / numBreakouts
		currIndex := uint8(index)
		// Construct config corresponding to each breakout group.
		group := oc.Component_Port_BreakoutMode_Group{
			Index:               &currIndex,
			BreakoutSpeed:       breakoutSpeed,
			NumBreakouts:        &u8numBreakouts,
			NumPhysicalChannels: &numPhysicalChannels,
		}
		// Add breakout group config to breakout config using index as key.
		// Index is strictly ordered staring from 0.
		breakoutGroups[currIndex] = &group

		// Get the interface config for all interfaces corresponding to current breakout group.
		for i := 1; i <= int(numBreakouts); i++ {
			intfName := fmt.Sprintf("%s%s/%s/%d", FrontPanelPortPrefix, slotPortLane[slotIndex], slotPortLane[portIndex], currLaneNumber)
			interfaceConfig[intfName], err = interfaceConfigForPort(t, dut, intfName, breakoutSpeed, fecMode(breakoutSpeed, numPhysicalChannels))
			if err != nil {
				return nil, err
			}
			offset := int(maxChannelsInGroup) / int(numBreakouts)
			currLaneNumber += offset
		}
		index++
	}

	// Get port ID.
	frontPanelPortToIndexMap, err := FrontPanelPortToIndexMappingForDevice(t, dut)
	if err != nil {
		return nil, errors.Errorf("failed to fetch front panel port to index mapping from device %v", testhelperDUTNameGet(dut))
	}
	if _, ok := frontPanelPortToIndexMap[port]; !ok {
		return nil, errors.Errorf("port %v not found in list of front panel port", port)
	}
	portIndex := frontPanelPortToIndexMap[port]

	// Construct component path config from created breakout groups.
	componentName := "1/" + strconv.Itoa(portIndex)
	componentConfig := map[string]*oc.Component{
		componentName: {
			Name: &componentName,
			Port: &oc.Component_Port{
				BreakoutMode: &oc.Component_Port_BreakoutMode{Group: breakoutGroups},
			},
		},
	}

	// Construct overall config from component and interface config.
	deviceConfig := &oc.Root{
		Interface: interfaceConfig,
		Component: componentConfig,
	}
	return deviceConfig, nil
}

// SpeedChangeOnlyPorts returns
// 1. Whether changing from currBrekaoutMode to newBreakoutMode is overall a speed change operation.
// 2. Number of ports that will result in speed change only if 1 is true.
func SpeedChangeOnlyPorts(t *testing.T, dut *ondatra.DUTDevice, port string, currBreakoutMode string, newBreakoutMode string) (bool, int, error) {
	t.Helper()
	// Get list of interfaces for current and new breakout modes.
	currPortInfo, err := ExpectedPortInfoForBreakoutMode(t, dut, port, currBreakoutMode)
	if err != nil {
		return false, 0, errors.Wrapf(err, "failed to get expected port information for breakout mode (%v) for port %v", currBreakoutMode, port)
	}
	if currPortInfo == nil {
		return false, 0, errors.Errorf("got empty port information for breakout mode %v for port %v", currBreakoutMode, port)
	}
	newPortInfo, err := ExpectedPortInfoForBreakoutMode(t, dut, port, newBreakoutMode)
	if err != nil {
		return false, 0, errors.Wrapf(err, "failed to get expected port information for breakout mode (%v) for port %v", newBreakoutMode, port)
	}
	if newPortInfo == nil {
		return false, 0, errors.Errorf("got empty port information for breakout mode %v for port %v", newBreakoutMode, port)
	}
	speedChangeOnlyPortCount := 0
	unchangedPortCount := 0
	for port, info := range currPortInfo {
		if _, ok := newPortInfo[port]; ok {
			if Uint16ListToString(info.PhysicalChannels) == Uint16ListToString(newPortInfo[port].PhysicalChannels) {
				if info.PortSpeed != newPortInfo[port].PortSpeed {
					speedChangeOnlyPortCount++
				} else {
					unchangedPortCount++
				}
			}
		} else {
			return false, 0, nil
		}
	}
	return ((speedChangeOnlyPortCount + unchangedPortCount) == len(currPortInfo)), speedChangeOnlyPortCount, nil
}

func breakoutModeSupportedTypes(breakoutMode string) (map[BreakoutType]bool, error) {
	supportedBreakoutTypes := map[BreakoutType]bool{
		Any: true,
	}
	if strings.Contains(breakoutMode, "+") {
		supportedBreakoutTypes[Mixed] = true
		supportedBreakoutTypes[Channelized] = true
	} else {
		supportedBreakoutTypes[NonMixed] = true
		values := strings.Split(breakoutMode, "x")
		if len(values) != 2 {
			return nil, errors.Errorf("invalid breakout format (%v)", breakoutMode)
		}
		numBreakouts, err := strconv.Atoi(values[0])
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing numBreakouts for breakout mode %v", breakoutMode)
		}
		if numBreakouts > 1 {
			supportedBreakoutTypes[Channelized] = true
		}
	}
	return supportedBreakoutTypes, nil
}

// RandomPortWithSupportedBreakoutModes attempts to get a random port from list of front panel ports
// that supports at least one more breakout mode other than the currently configured breakout mode.
func RandomPortWithSupportedBreakoutModes(t *testing.T, dut *ondatra.DUTDevice, params *RandomPortWithSupportedBreakoutModesParams) (*RandomPortBreakoutInfo, error) {
	t.Helper()
	var portList []string
	newBreakoutType := Unset
	currBreakoutType := Unset
	reqSpeedChangeOnlyPortCount := 0
	// Parse additional parameters
	if params != nil {
		portList = params.PortList
		newBreakoutType = params.NewBreakoutType
		currBreakoutType = params.CurrBreakoutType
		reqSpeedChangeOnlyPortCount = params.SpeedChangeOnlyPortCount
	}
	// A port is randomly picked from given list (we start with all front panel ports if portList is not specified).
	var err error
	if len(portList) == 0 {
		portList, err = FrontPanelPortListForDevice(t, dut)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch front panel port list")
		}
	}

	// Maintain a map of interfaces to allow fast deletion of port from portList (if it does not meet the test requirements).
	portMap := make(map[string]bool)
	for _, port := range portList {
		portMap[port] = true
	}

	// Keep trying to get a random port till one with at least one supported breakout mode is found.
	var port, breakoutMode, currBreakoutMode string
	for len(portMap) != 0 {
		// Construct portList from port map.
		var portList []string
		for p := range portMap {
			portList = append(portList, p)
		}
		randomInterfaceParams := RandomInterfaceParams{
			PortList: portList,
			IsParent: true,
		}
		port, err = RandomInterface(t, dut, &randomInterfaceParams)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch random interface")
		}

		// Get current breakout mode for the port.
		currBreakoutMode, err = CurrentBreakoutModeForPort(t, dut, port)
		if err != nil || currBreakoutMode == "" {
			return nil, errors.Wrapf(err, "failed to fetch current breakout mode for port %v", port)
		}

		// Supported breakout modes are not required for cases where only the current breakout mode for
		// a port is of importance.
		// Eg: Port sfec tests require a channelized port but do not perform any breakout operations,
		// so the port is not required to support other breakout modes.
		if newBreakoutType == Unset {
			return &RandomPortBreakoutInfo{
					PortName:              port,
					CurrBreakoutMode:      currBreakoutMode,
					SupportedBreakoutMode: "",
				},
				nil
		}

		// Check if current breakout mode is of the requested type.
		if currBreakoutType != Any {
			currBreakoutTypes, err := breakoutModeSupportedTypes(currBreakoutMode)
			if err != nil {
				return nil, errors.Errorf("failed to get types supported by current breakout mode %v", currBreakoutMode)
			}

			// Do not consider port if requested breakout mode type is not supported by the current breakout mode.
			if _, ok := currBreakoutTypes[currBreakoutType]; !ok {
				delete(portMap, port)
				continue
			}
		}

		// Get supported breakout modes for the port.
		supportedBreakoutModes, err := SupportedBreakoutModesForPort(t, dut, port, newBreakoutType)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch supported breakout modes for port %v", port)
		}
		if len(supportedBreakoutModes) == 0 {
			if newBreakoutType == Mixed {
				log.Infof("No supported mixed breakout modes found for port %v!", port)
				delete(portMap, port)
				continue
			} else {
				// Each port must support at least one breakout mode.
				return nil, errors.Errorf("no supported breakout modes found for port %v", port)
			}
		}

		// Get a supported breakout mode different from current breakout mode.
		// Ignore breakout modes that will only result in a speed change.
		for _, mode := range supportedBreakoutModes {
			speedChangeOnly, speedChangeOnlyPortCount, err := SpeedChangeOnlyPorts(t, dut, port, currBreakoutMode, mode)
			if err != nil {
				return nil, errors.Errorf("failed to determine if mode %v is a port speed change only from mode %v for port %v: %v", mode, currBreakoutMode, port, err)
			}
			if mode != currBreakoutMode {
				if newBreakoutType != SpeedChangeOnly {
					if !speedChangeOnly {
						breakoutMode = mode
						break
					}
				} else {
					if speedChangeOnly && speedChangeOnlyPortCount >= reqSpeedChangeOnlyPortCount {
						breakoutMode = mode
						break
					}
				}
			}
		}
		if breakoutMode != "" {
			// Found a supported breakout mode other than current breakout mode.
			break
		}

		log.Infof("No other supported breakout mode found for port %v", port)
		delete(portMap, port)
	}
	if breakoutMode == "" {
		return nil, errors.Errorf("no ports with supported breakout modes found")
	}

	log.Infof("Using interface %v with current breakout mode %v, new breakout mode: %v", port, currBreakoutMode, breakoutMode)
	return &RandomPortBreakoutInfo{
			PortName:              port,
			CurrBreakoutMode:      currBreakoutMode,
			SupportedBreakoutMode: breakoutMode,
		},
		nil
}

// PhysicalPort returns the physical port corresponding to the given interface.
func PhysicalPort(t *testing.T, dut *ondatra.DUTDevice, interfaceName string) (string, error) {
	t.Helper()
	portToIndexMap, err := FrontPanelPortToIndexMappingForDevice(t, dut)
	if err != nil {
		return "", errors.Wrap(err, "failed to fetch front panel port to index mapping")
	}
	if _, ok := portToIndexMap[interfaceName]; !ok {
		return "", errors.Errorf("no entry found for interface %v in front panel port list", interfaceName)
	}
	return "1/" + strconv.Itoa(portToIndexMap[interfaceName]), nil
}

// BreakoutStateInfoForPort returns the state values of physical channels and operational status information for ports in a given breakout mode.
func BreakoutStateInfoForPort(t *testing.T, dut *ondatra.DUTDevice, port string, currBreakoutMode string) (map[string]*PortBreakoutInfo, error) {
	t.Helper()
	// Get list of interfaces for breakout mode.
	portInfo, err := ExpectedPortInfoForBreakoutMode(t, dut, port, currBreakoutMode)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get expected port information for breakout mode (%v) for port %v", currBreakoutMode, port)
	}
	if portInfo == nil {
		return nil, errors.Errorf("got empty port information for breakout mode %v for port %v", currBreakoutMode, port)
	}
	// Get physical channels and operational statuses for list of ports in given breakout mode.
	for p := range portInfo {
		physicalChannels := testhelperIntfPhysicalChannelsGet(t, dut, p)
		operStatus := testhelperIntfOperStatusGet(t, dut, p)
		portSpeed := testhelperStatePortSpeedGet(t, dut, p)
		portInfo[p] = &PortBreakoutInfo{physicalChannels, operStatus, portSpeed}
	}
	return portInfo, nil
}

// WaitForInterfaceState polls interface oper-status until it matches the expected oper-status.
func WaitForInterfaceState(t *testing.T, dut *ondatra.DUTDevice, intfName string, expectedOperSatus oc.E_Interface_OperStatus, timeout time.Duration) error {
	t.Helper()
	// Verify oper-status by polling interface oper-status.
	var got oc.E_Interface_OperStatus
	for start := time.Now(); time.Since(start) < timeout; {
		if got = testhelperIntfOperStatusGet(t, dut, intfName); got == expectedOperSatus {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.Errorf("port oper-status match failed for port %v. got: %v, want: %v", intfName, got, expectedOperSatus)
}

// TransceiverNumberForPort fetches the transceiver corresponding to the port.
func TransceiverNumberForPort(t *testing.T, dut *ondatra.DUTDevice, port string) (int, error) {
	if !IsFrontPanelPort(port) {
		return 0, errors.Errorf("port: %v is not a front panel port", port)
	}

	// Hardware port is of the format 1/X, where X represents the
	// transceiver number.
	prefix := "1/"
	hardwarePort := testhelperIntfHardwarePortGet(t, dut, port)
	if !strings.HasPrefix(hardwarePort, prefix) {
		return 0, errors.Errorf("invalid hardware-port: %v for port: %v. It must start with %v", hardwarePort, port, prefix)
	}
	transceiver, err := strconv.Atoi(strings.TrimPrefix(hardwarePort, prefix))
	if err != nil {
		return 0, errors.Wrapf(err, "unable to convert %v to integer for port: %v", strings.TrimPrefix(hardwarePort, prefix), port)
	}
	return transceiver, nil
}

// IsParentPort returns whether the specified port is a parent port or not.
func IsParentPort(t *testing.T, dut *ondatra.DUTDevice, port string) (bool, error) {
	if !IsFrontPanelPort(port) {
		return false, errors.Errorf("port: %v is not a front panel port", port)
	}

	slotPortLane, err := slotPortLaneForPort(port)
	if err != nil {
		return false, err
	}
	currLaneNumber, err := strconv.Atoi(slotPortLane[laneIndex])
	if err != nil {
		return false, errors.Wrapf(err, "failed to convert lane number (%v) to int", currLaneNumber)
	}
	// Lane number for a parent port is always 1.
	return currLaneNumber == 1, nil
}

// ParentPortNumber returns the port number of the parent of the port.
func ParentPortNumber(port string) (string, error) {
	slotPortLane, err := slotPortLaneForPort(port)
	if err != nil {
		return "", err
	}
	return slotPortLane[portIndex], nil
}

// PortPMDFromModel returns the port pmdtype from the model.
func PortPMDFromModel(t *testing.T, dut *ondatra.DUTDevice, port string) (string, error) {
	return testhelperPortPmdTypeGet(t, dut, port)
}

//Adding function to manually convert string to uint32
func lower(c byte) byte {
	return c | ('x' - 'X')
}
func conversionTouint32(s string)(uint32,error) {
	maxVal := ^uint32(0)
	fmt.Printf("maxval: %d",maxVal)
	if s == "" {
		return 0,errors.New("StringConvUint32:StringIsNill")
	}
	var n uint32
	for _, c := range []byte(s) {
		var d byte
		switch {
		case '0' <= c && c <= '9':
			d = c - '0'
		case 'a' <= lower(c) && lower(c) <= 'z':
			d = lower(c) - 'a' + 10
		default:
			return 0,errors.New("StringConvUint32:switcherror")
		}
		if d >= byte(10) {
			return 0,errors.New("StringConvUint32:ByteError")
		}
		if n >= maxVal {
			// n*base overflows
			return 0,errors.New("StringConvUint32:MaxValueRangeError")
		}
		n *= uint32(10)
		n1 := n + uint32(d)
		if n1 < n || n1 > maxVal {
			// n+d overflows
			return 0,errors.New("StringConvUint32:RangeError")
		}
		n = n1
	}
    return n,nil

}

//Adding Function to manually conver string to uint8
func portStringToUint8(portStr string) (uint8, error) {
    var result uint8
    for i := 0; i < len(portStr); i++ {
        if portStr[i] < '0' || portStr[i] > '9' {
            return 0, fmt.Errorf("invalid character '%c' in port number", portStr[i])
        }
        result = result*10 + uint8(portStr[i]-'0')
    }
    if result > math.MaxUint8 {
        return 0, fmt.Errorf("port number %d is out of uint8 range", result)
    }
    return result, nil
}

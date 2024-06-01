package testhelper

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi/oc"
)

// LoggingInfo contains a remote server addresses to be used for logging.
type LoggingInfo struct {
	IPv4RemoteAddresses []string
	IPv6RemoteAddresses []string
}

// CPUInfo contains CPU-related information.
type CPUInfo struct {
	Index           uint32
	MaxAverageUsage uint8
}

// MemoryInfo contains memory related information.
type MemoryInfo struct {
	Physical                     uint64
	FreeThreshold                uint64
	UsedThreshold                uint64
	CorrectableEccErrorThreshold uint64
}

// NTPServerInfo returns NTP server related information.
type NTPServerInfo struct {
	IPv4Address      []string
	IPv6Address      []string
	StratumThreshold uint8
}

// FPGAInfo consists of FPGA related information.
type FPGAInfo struct {
	Name                 string
	Manufacturer         string
	Description          string
	FirmwareVersionRegex string
	ResetCauseNum        int
}

// IntegratedCircuitInfo consists of integrated-circuit related information.
type IntegratedCircuitInfo struct {
	Name                           string
	CorrectedParityErrorsThreshold uint64
}

// Threshold32 consists of the minimum and maximum thresholds as a float32.
type Threshold32 struct {
	Min float32
	Max float32
}

// Threshold64 consists of the minimum and maximum thresholds as a float64.
type Threshold64 struct {
	Min float64
	Max float64
}

// TemperatureSensorInfo consists of temperature sensor related information.
type TemperatureSensorInfo struct {
	Name           string
	Location       string
	MaxTemperature float64
}

// SecurityComponentInfo consists of security component related information.
type SecurityComponentInfo struct {
	Name string
}

// Threshold is any numeric type that is used as a lower or upper threshold.
type Threshold interface {
	float64 | uint64 | uint32
}

// Thresholds encapsulates a set of inclusive lower and upper thresholds.
type Thresholds[T Threshold] struct {
	HasLo bool
	Lo    T
	HasHi bool
	Hi    T
}

// SmartDataInfo consists of storage device SMART data related information.
type SmartDataInfo struct {
	WriteAmplificationFactorThresholds Thresholds[float64]
	RawReadErrorRateThresholds         Thresholds[float64]
	ThroughputPerformanceThresholds    Thresholds[float64]
	ReallocatedSectorCountThresholds   Thresholds[uint64]
	PowerOnSecondsThresholds           Thresholds[uint64]
	SSDLifeLeftThresholds              Thresholds[uint64]
	AvgEraseCountThresholds            Thresholds[uint32]
	MaxEraseCountThresholds            Thresholds[uint32]
}

// StorageDeviceInfo consists of storage device related information.
type StorageDeviceInfo struct {
	Name              string
	IsRemovable       bool
	IOErrorsThreshold uint64
	SmartDataInfo     SmartDataInfo
}

// FanInfo consists of fan related information.
type FanInfo struct {
	Name        string
	IsRemovable bool
	Parent      string
	Location    string
	MaxSpeed    uint32
}

// PcieInfo consists of PCIe device related information.
type PCIeInfo struct {
	Name string
}

// FanTrayInfo consists of fan tray related information.
type FanTrayInfo struct {
	Name        string
	IsRemovable bool
	Parent      string
	Location    string
}

// MountPointInfo returns mount points related information.
type MountPointInfo struct {
	Name string
}

// HardwareInfo contains hardware components related information.
type HardwareInfo struct {
	Fans     []FanInfo
	Fantrays []FanTrayInfo
	FPGAs    []FPGAInfo
	ICs      []IntegratedCircuitInfo
	PCIe     []PCIeInfo
	Security []SecurityComponentInfo
	Storage  []StorageDeviceInfo
	CPU      []TemperatureSensorInfo
	Heatsink []TemperatureSensorInfo
	Exhaust  []TemperatureSensorInfo
	Inlet    []TemperatureSensorInfo
	Dimm     []TemperatureSensorInfo
}

// SystemInfo consists of system related information.
type SystemInfo struct {
	RebootTime     time.Duration
	CPUInfo        []CPUInfo
	LoggingInfo    LoggingInfo
	MemInfo        MemoryInfo
	MountPointInfo []MountPointInfo
	NTPServerInfo  []NTPServerInfo
}

// PlatformInfo contains platform specific information.
type PlatformInfo struct {
	SystemInfo   SystemInfo
	HardwareInfo HardwareInfo
	build        func(t *testing.T, dut *ondatra.DUTDevice, p *PlatformInfo) error
}

// Lanes represents number of lanes.
type Lanes int

// PMDProperty contain PMD information.
type PMDProperty struct {
	SupportedSpeeds        map[Lanes][]oc.E_IfEthernet_ETHERNET_SPEED
	SupportedBreakoutModes []string
	CollateralFlap         bool
}

type PMDType string

var pmdProperties = map[PMDType]*PMDProperty{
	"ETH_2X400GBASE_PSM4": &PMDProperty{
		CollateralFlap: false,
		SupportedSpeeds: map[Lanes][]oc.E_IfEthernet_ETHERNET_SPEED{
			4: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_400GB},
			2: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_200GB},
		},
		SupportedBreakoutModes: []string{"2x400G", "4x200G", "1x400G(4)+2x200G(4)", "2x200G(4),+1x400G(4)"},
	},
	"ETH_2X400GBASE_DR4": &PMDProperty{
		CollateralFlap: false,
		SupportedSpeeds: map[Lanes][]oc.E_IfEthernet_ETHERNET_SPEED{
			4: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_400GB},
			2: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_200GB},
			1: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_100GB},
		},
		SupportedBreakoutModes: []string{"8x100G", "2x400G", "4x200G", "1x400G(4)+2x200G(4)", "2x200G(4)+1x400G(4)"},
	},
	"ETH_2X200GBASE_BGR4": &PMDProperty{
		CollateralFlap: false,
		SupportedSpeeds: map[Lanes][]oc.E_IfEthernet_ETHERNET_SPEED{
			4: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_200GB},
			2: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_50GB},
		},
		SupportedBreakoutModes: []string{"1x200G(4)+2x50G(4)", "2x50G(4)+1x200G(4)"},
	},

	"ETH_200GBASE_BSM8": &PMDProperty{
		CollateralFlap: false,
		SupportedSpeeds: map[Lanes][]oc.E_IfEthernet_ETHERNET_SPEED{
			2: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_50GB},
		},
		SupportedBreakoutModes: []string{"1x200G(4)+2x50G(4)", "2x50G(4)+1x200G(4)"},
	},
	"ETH_2X400GBASE_CDGR4_PLUS": &PMDProperty{
		CollateralFlap: true,
		SupportedSpeeds: map[Lanes][]oc.E_IfEthernet_ETHERNET_SPEED{
			4: []oc.E_IfEthernet_ETHERNET_SPEED{
				oc.IfEthernet_ETHERNET_SPEED_SPEED_400GB,
				oc.IfEthernet_ETHERNET_SPEED_SPEED_200GB,
				oc.IfEthernet_ETHERNET_SPEED_SPEED_100GB,
			},
		},
		SupportedBreakoutModes: []string{"2x400G", "2x200G", "2x100G", "1x400G(4)+1x200G(4)", "1x400G(4)+1x100G(4)", "1x200G(4)+1x400G(4)", "1x200G(4)+1x100G(4)", "1x100G(4)+1x400G(4)", "1x100G(4)+1x200G(4)"},
	},
	"ETH_2X400GBASE_CR4": &PMDProperty{
		CollateralFlap: false,
		SupportedSpeeds: map[Lanes][]oc.E_IfEthernet_ETHERNET_SPEED{
			4: []oc.E_IfEthernet_ETHERNET_SPEED{oc.IfEthernet_ETHERNET_SPEED_SPEED_400GB},
		},
		SupportedBreakoutModes: []string{"2x400G"},
	},
}

// PortProperties contains front panel port information.
type PortProperty struct {
	Index               int
	DefaultBreakoutMode string
	MediaType           string
}

func (p *PortInfo) PMDProperty(pmdType PMDType) (*PMDProperty, error) {
	if _, ok := p.PMD[pmdType]; !ok {
		return nil, fmt.Errorf("PMDType : %v not supported by the PortInfo", pmdType)
	}
	if v, ok := pmdProperties[pmdType]; ok {
		ret := *v
		return &ret, nil
	}
	return nil, fmt.Errorf("PMDType : %v not defined in pmdProperties", pmdType)
}

// PortInfo contains port related information.
type PortInfo struct {
	MaxLanes       int
	PortProperties map[string]*PortProperty
	PMD            map[PMDType]bool
	build          func(t *testing.T, dut *ondatra.DUTDevice, p *PortInfo) error
}

type infoBuilder interface {
	newPlatformInfo(t *testing.T, dut *ondatra.DUTDevice) (*PlatformInfo, error)
	newPortInfo(t *testing.T, dut *ondatra.DUTDevice) (*PortInfo, error)
}

var platforms = map[string]infoBuilder{}

func registerPlatform(platformName string, val infoBuilder) {
	if _, ok := platforms[platformName]; ok {
		log.Fatalf("platform : %v already registered.", platformName)
	}
	platforms[platformName] = val
}

// NewPortInfo creates a new PortInfo.
func NewPortInfo(t *testing.T, dut *ondatra.DUTDevice, platformName string) (*PortInfo, error) {
	val, ok := platforms[platformName]
	if !ok {
		return nil, fmt.Errorf("PortInfo struct not found for : %v", platformName)
	}
	return val.newPortInfo(t, dut)
}

// NewPlatformInfo creates a new PlatformInfo.
func NewPlatformInfo(t *testing.T, dut *ondatra.DUTDevice, platformName string) (*PlatformInfo, error) {
	val, ok := platforms[platformName]
	if !ok {
		return nil, fmt.Errorf("PlatformInfo struct not found for : %v", platformName)
	}
	return val.newPlatformInfo(t, dut)
}

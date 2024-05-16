package testhelper

import (
	"fmt"
	"strings"
)

// Software Component APIs.

// SwitchNameRegex returns the regex for switch name.
func SwitchNameRegex() string {
	return ""
}

// ImageVersionRegex returns the regular expressions for the image version of the switch.
func ImageVersionRegex() []string {
	return []string{
		"^pins_daily_(20\\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])_([0-1]?[0-9]|2[0-3])_RC(\\d{2})$",
		"^pins_release_(20\\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])_([0-1]?[0-9]|2[0-3])_(prod|dev)_RC(\\d{2})$",
	}
}

// System APIs.

// GetIndex returns the CPU index.
func (c CPUInfo) GetIndex() uint32 {
	return c.Index
}

// GetMaxAverageUsage returns the maximum CPU average usage.
func (c CPUInfo) GetMaxAverageUsage() uint8 {
	return c.MaxAverageUsage
}




// GetPhysical returns the expected physical memory.
func (m MemoryInfo) GetPhysical() uint64 {
	return m.Physical
}

// GetFreeThreshold returns the free memory threshold.
func (m MemoryInfo) GetFreeThreshold() uint64 {
	return m.FreeThreshold
}

// GetUsedThreshold returns the used memory threshold.
func (m MemoryInfo) GetUsedThreshold() uint64 {
	return m.UsedThreshold
}

// GetCorrectableEccErrorThreshold returns the correctable ECC error threshold.
func (m MemoryInfo) GetCorrectableEccErrorThreshold() uint64 {
	return m.CorrectableEccErrorThreshold
}


// GetName returns the name of the mount point.
func (m MountPointInfo) GetName() string {
	return m.Name
}


// GetIPv4Address returns NTP server's IPv4 addresses.
func (n NTPServerInfo) GetIPv4Address() []string {
	return n.IPv4Address
}

// GetIPv6Address returns NTP server's IPv6 addresses.
func (n NTPServerInfo) GetIPv6Address() []string {
	return n.IPv6Address
}

// GetStratumThreshold returns the stratum threshold for the NTP server.
func (n NTPServerInfo) GetStratumThreshold() uint8 {
	return n.StratumThreshold
}


// Integrated Circuit APIs.

// GetName returns the integrated-circuit name.
func (i IntegratedCircuitInfo) GetName() string {
	return i.Name
}

// GetCorrectedParityErrorsThreshold returns the corrected-parity-error
// threshold for the integrated-circuit.
func (i IntegratedCircuitInfo) GetCorrectedParityErrorsThreshold() uint64 {
	return i.CorrectedParityErrorsThreshold
}

// FPGA APIs.

// GetName returns the FPGA name.
func (f FPGAInfo) GetName() string {
	return f.Name
}

// GetMfgName returns the FPGA manufacturer.
func (f FPGAInfo) GetMfgName() string {
	return f.Manufacturer
}

// GetDescription returns the FPGA description.
func (f FPGAInfo) GetDescription() string {
	return f.Description
}

// GetFirmwareVersionRegex returns the FPGA firmware version regex.
func (f FPGAInfo) GetFirmwareVersionRegex() string {
	return f.FirmwareVersionRegex
}

// GetResetCauseNum returns the number of reset causes reported by the FPGA.
func (f FPGAInfo) GetResetCauseNum() int {
	return f.ResetCauseNum
}


// GetMin returns the minimum threshold for the power information.
func (p Threshold32) GetMin() float32 {
	return p.Min
}

// GetMax returns the maximum threshold for the power information.
func (p Threshold32) GetMax() float32 {
	return p.Max
}

// GetMin returns the minimum threshold for the power information.
func (p Threshold64) GetMin() float64 {
	return p.Min
}

// GetMax returns the maximum threshold for the power information.
func (p Threshold64) GetMax() float64 {
	return p.Max
}

// TemperatureSensorType defines the type of temperature sensors.
type TemperatureSensorType int

// Type of temperature sensors.
const (
	CPUTempSensor TemperatureSensorType = iota
	HeatsinkTempSensor
	ExhaustTempSensor
	InletTempSensor
	DimmTempSensor
)

// GetName returns the temperature sensor name.
func (t TemperatureSensorInfo) GetName() string {
	return t.Name
}

// GetLocation returns the temperature sensor location.
func (t TemperatureSensorInfo) GetLocation() string {
	return t.Location
}

// GetMaxTemperature returns the temperature threshold for the temperature sensor.
func (t TemperatureSensorInfo) GetMaxTemperature() float64 {
	return t.MaxTemperature
}


// GetName returns the security component name.
func (s SecurityComponentInfo) GetName() string {
	return s.Name
}


// IsValid checks if a value is in the thresholds.
func (t Thresholds[T]) IsValid(v T) bool {
	if t.HasLo && v < t.Lo {
		return false
	}
	if t.HasHi && v > t.Hi {
		return false
	}
	return true
}

// ThresholdsToString is a helper method to convert a set of thresholds to a readable string.
func (t Thresholds[T]) String() string {
	var sb strings.Builder
	if t.HasLo {
		sb.WriteString("lo:>=")
		sb.WriteString(fmt.Sprintf("%v", t.Lo))
	} else {
		sb.WriteString("(no lo)")
	}
	sb.WriteString(" ")

	if t.HasHi {
		sb.WriteString("hi:<=")
		sb.WriteString(fmt.Sprintf("%v", t.Hi))
	} else {
		sb.WriteString("(no hi)")
	}

	return sb.String()
}

// GetWriteAmplificationFactorThresholds returns the write amplification factor thresholds.
func (s SmartDataInfo) GetWriteAmplificationFactorThresholds() Thresholds[float64] {
	return s.WriteAmplificationFactorThresholds
}

// GetRawReadErrorRateThresholds returns the raw read error rate thresholds.
func (s SmartDataInfo) GetRawReadErrorRateThresholds() Thresholds[float64] {
	return s.RawReadErrorRateThresholds
}

// GetThroughputPerformanceThresholds returns the throughput performance thresholds.
func (s SmartDataInfo) GetThroughputPerformanceThresholds() Thresholds[float64] {
	return s.ThroughputPerformanceThresholds
}

// GetReallocatedSectorCountThresholds returns the throughput performance thresholds.
func (s SmartDataInfo) GetReallocatedSectorCountThresholds() Thresholds[uint64] {
	return s.ReallocatedSectorCountThresholds
}

// GetPowerOnSecondsThresholds returns the throughput performance thresholds.
func (s SmartDataInfo) GetPowerOnSecondsThresholds() Thresholds[uint64] {
	return s.PowerOnSecondsThresholds
}

// GetSsdLifeLeftThresholds returns the SSD life left thresholds.
func (s SmartDataInfo) GetSsdLifeLeftThresholds() Thresholds[uint64] {
	return s.SSDLifeLeftThresholds
}

// GetAvgEraseCountThresholds returns the average erase count thresholds.
func (s SmartDataInfo) GetAvgEraseCountThresholds() Thresholds[uint32] {
	return s.AvgEraseCountThresholds
}

// GetMaxEraseCountThresholds returns the average erase count thresholds.
func (s SmartDataInfo) GetMaxEraseCountThresholds() Thresholds[uint32] {
	return s.MaxEraseCountThresholds
}

// GetName returns the storage device name.
func (s StorageDeviceInfo) GetName() string {
	return s.Name
}

// GetIsRemovable returns whether the storage device is removable or not.
func (s StorageDeviceInfo) GetIsRemovable() bool {
	return s.IsRemovable
}

// GetIoErrorsThreshold returns the threshold for storage device I/O errors.
func (s StorageDeviceInfo) GetIoErrorsThreshold() uint64 {
	return s.IOErrorsThreshold
}

// GetSmartDataInfo returns the SMART data info.
func (s StorageDeviceInfo) GetSmartDataInfo() SmartDataInfo {
	return s.SmartDataInfo
}


// GetName returns the fan name.
func (f FanInfo) GetName() string {
	return f.Name
}

// GetIsRemovable returns whether the fan is removable or not.
func (f FanInfo) GetIsRemovable() bool {
	return f.IsRemovable
}

// GetLocation returns the location of the fan.
func (f FanInfo) GetLocation() string {
	return f.Location
}

// GetMaxSpeed returns the maximum speed of the fan.
func (f FanInfo) GetMaxSpeed() uint32 {
	return f.MaxSpeed
}

// GetParent returns the parent component of the fan.
func (f FanInfo) GetParent() string {
	return f.Parent
}

// GetName returns the fan tray name.
func (f FanTrayInfo) GetName() string {
	return f.Name
}

// GetIsRemovable returns whether the fan tray is removable or not.
func (f FanTrayInfo) GetIsRemovable() bool {
	return f.IsRemovable
}

// GetParent returns the parent component of the fan tray.
func (f FanTrayInfo) GetParent() string {
	return f.Parent
}

// GetLocation returns the location of the fan tray.
func (f FanTrayInfo) GetLocation() string {
	return f.Location
}



// GetName returns the PCIe device name.
func (p PCIeInfo) GetName() string {
	return p.Name
}

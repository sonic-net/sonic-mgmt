package testhelper

import (
	"testing"

	"github.com/openconfig/ondatra"
)

type defaultPlatform struct {
	infoBuilder
	platformInfo PlatformInfo
	portInfo     PortInfo
}

var platform = defaultPlatform{
	platformInfo: PlatformInfo{
		SystemInfo: SystemInfo{
			RebootTime: 360000000000,
		},
		HardwareInfo: HardwareInfo{},
	},
	portInfo: PortInfo{
		MaxLanes: 8,
		PMD: map[PMDType]bool{
			"ETH_200GBASE_BSM8":         true,
			"ETH_2X200GBASE_BGR4":       true,
			"ETH_2X400GBASE_CDGR4_PLUS": true,
			"ETH_2X400GBASE_CR4":        true,
			"ETH_2X400GBASE_DR4":        true,
			"ETH_2X400GBASE_PSM4":       true,
		},
		PortProperties: map[string]*PortProperty{},
	},
}

func (d *defaultPlatform) newPlatformInfo(t *testing.T, dut *ondatra.DUTDevice) (*PlatformInfo, error) {
	ret := d.platformInfo
	return &ret, nil
}

func (d *defaultPlatform) newPortInfo(t *testing.T, dut *ondatra.DUTDevice) (*PortInfo, error) {
	ret := d.portInfo
	return &ret, nil
}

func init() {
	registerPlatform("default", &platform)
}

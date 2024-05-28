package platforms_software_component_test

import (
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/testt"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"github.com/pkg/errors"

	syspb "github.com/openconfig/gnoi/system"
)

func verifyImageVersion(version string) error {
	regex := testhelper.ImageVersionRegex()

	for _, r := range regex {
		if match, err := regexp.MatchString(r, version); err == nil && match {
			return nil
		}
	}

	return errors.Errorf("version match failed for %v", version)
}

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func TestGetOperatingSystemDefaultInfo(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("ba4294cc-1174-44c4-88c1-2d3cf8f000a0").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	validStorageSides := map[string]bool{
		"SIDE_A": true,
		"SIDE_B": true,
	}

	// Software version format: <int>.<int>.<int>-planetbde
	swVersionRegex := `^(\d+\.)(\d+\.)(\d+)(-planetbde)$`
	expr, err := regexp.Compile(swVersionRegex)
	if err != nil {
		t.Errorf("Internal error: Invalid regex %v for OS component (%v)", swVersionRegex, err)
	}

	// GPINs switch consists of 2 OS paritions - side A and B. The active partition is referenced
	// using OS component Openconfig path with key as "os0" and the inactive partition is
	// referenced using the OS component Openconfig path with key as "os1".
	tests := []struct {
		key                string
		expectedOperStatus oc.E_PlatformTypes_COMPONENT_OPER_STATUS
	}{
		{
			key:                "os0",
			expectedOperStatus: oc.PlatformTypes_COMPONENT_OPER_STATUS_ACTIVE,
		},
		{
			key:                "os1",
			expectedOperStatus: oc.PlatformTypes_COMPONENT_OPER_STATUS_INACTIVE,
		},
	}

	for _, tc := range tests {
		componentPath := gnmi.OC().Component(tc.key)

		name := gnmi.Get(t, dut, componentPath.Name().State())
		if name != tc.key {
			t.Errorf("OS component (%v) name match failed! got:%v, want:%v", tc.key, name, tc.key)
		}

		operStatus := gnmi.Get(t, dut, componentPath.OperStatus().State())
		if operStatus != tc.expectedOperStatus {
			t.Errorf("OS component (%v) oper-status match failed! got:%v, want:%v", tc.key, operStatus, tc.expectedOperStatus)
		}

		parent := gnmi.Get(t, dut, componentPath.Parent().State())
		if expectedParent := "chassis"; parent != expectedParent {
			t.Errorf("OS component (%v) parent match failed! got:%v, want:%v", tc.key, parent, expectedParent)
		}

		swVersion := gnmi.Get(t, dut, componentPath.SoftwareVersion().State())
		if expr != nil {
			if match := expr.MatchString(swVersion); !match {
				t.Errorf("OS component (%v) software version match failed! got:%v, want(Regex):%v", tc.key, swVersion, swVersionRegex)
			}
		}

		osType := gnmi.Get(t, dut, componentPath.Type().State())
		if expectedOsType := oc.PlatformTypes_OPENCONFIG_SOFTWARE_COMPONENT_OPERATING_SYSTEM; osType != expectedOsType {
			t.Errorf("OS component (%v) type match failed! got:%v, want:%v", tc.key, osType, expectedOsType)
		}

		storageSide := testhelper.ComponentStorageSide(t, dut, name)
		if _, ok := validStorageSides[storageSide]; ok {
			// Storage side needs to be unique for each OS component. Remove the current
			// side from valid storage sides map.
			delete(validStorageSides, storageSide)
		} else {
			t.Errorf("Invalid storage-side for OS component (%v)! got:%v", tc.key, storageSide)
		}
	}
}

func TestGetBootloaderDefaultInfo(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("d66c9503-4458-45aa-b816-fb75ed01e46d").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	key := "boot_loader"
	componentPath := gnmi.OC().Component(key)

	name := gnmi.Get(t, dut, componentPath.Name().State())
	if name != key {
		t.Errorf("Bootloader component name match failed! got:%v, want:%v", name, key)
	}

	parent := gnmi.Get(t, dut, componentPath.Parent().State())
	if expectedParent := "chassis"; parent != expectedParent {
		t.Errorf("Bootloader component parent match failed! got:%v, want:%v", parent, expectedParent)
	}

	swVersion := gnmi.Get(t, dut, componentPath.SoftwareVersion().State())
	// Version format: <int>.<int>.*
	swVersionRegex := `^(\d+\.)(\d+\.).*$`
	if match, err := regexp.MatchString(swVersionRegex, swVersion); err != nil || !match {
		t.Errorf("Bootloader component software version match failed! got:%v, want(Regex):%v %v", swVersion, swVersionRegex, err)
	}

	compType := gnmi.Get(t, dut, componentPath.Type().State())
	if expectedCompType := oc.PlatformTypes_OPENCONFIG_SOFTWARE_COMPONENT_BOOT_LOADER; compType != expectedCompType {
		t.Errorf("Bootloader component type match failed! got:%v, want:%v", compType, expectedCompType)
	}
}

func TestGetNetworkStackDefaultInfo(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("092c1229-c8a4-4941-bbd8-a7fe1ae79a48").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	validStorageSides := map[string]bool{
		"SIDE_A": true,
		"SIDE_B": true,
	}

	// GPINs switch consists of 2 paritions - side A and B. The active partition is referenced
	// using network stack component Openconfig path with key as "network_stack0" and the
	// inactive partition is referenced using network stack component Openconfig path with key as
	// "network_stack1".
	tests := []struct {
		key                string
		expectedOperStatus oc.E_PlatformTypes_COMPONENT_OPER_STATUS
	}{
		{
			key:                "network_stack0",
			expectedOperStatus: oc.PlatformTypes_COMPONENT_OPER_STATUS_ACTIVE,
		},
		{
			key:                "network_stack1",
			expectedOperStatus: oc.PlatformTypes_COMPONENT_OPER_STATUS_INACTIVE,
		},
	}

	for _, tc := range tests {
		componentPath := gnmi.OC().Component(tc.key)

		name := gnmi.Get(t, dut, componentPath.Name().State())
		if name != tc.key {
			t.Errorf("Network stack component (%v) name match failed! got:%v, want:%v", tc.key, name, tc.key)
		}

		operStatus := gnmi.Get(t, dut, componentPath.OperStatus().State())
		if operStatus != tc.expectedOperStatus {
			t.Errorf("Network stack component (%v) oper-status match failed! got:%v, want:%v", tc.key, operStatus, tc.expectedOperStatus)
		}

		parent := gnmi.Get(t, dut, componentPath.Parent().State())
		if expectedParent := "chassis"; parent != expectedParent {
			t.Errorf("Network stack component (%v) parent match failed! got:%v, want:%v", tc.key, parent, expectedParent)
		}

		swVersion := gnmi.Get(t, dut, componentPath.SoftwareVersion().State())
		// Image version check is applicable to only for active image in the current run. Refer b/221157028.
		if operStatus == oc.PlatformTypes_COMPONENT_OPER_STATUS_ACTIVE {
			if err := verifyImageVersion(swVersion); err != nil {
				t.Errorf("Network stack component (%v) software version match failed! got:%v, want(Regex):%v", tc.key, swVersion, testhelper.ImageVersionRegex())
			}
		}

		networkStackType := gnmi.Get(t, dut, componentPath.Type().State())
		if expectedNetworkStackType := oc.PlatformTypes_OPENCONFIG_SOFTWARE_COMPONENT_SOFTWARE_MODULE; networkStackType != expectedNetworkStackType {
			t.Errorf("Network stack component (%v) type match failed! got:%v, want:%v", tc.key, networkStackType, expectedNetworkStackType)
		}

		moduleType := gnmi.Get(t, dut, componentPath.SoftwareModule().ModuleType().State())
		if expectedModuleType := oc.PlatformSoftware_SOFTWARE_MODULE_TYPE_USERSPACE_PACKAGE_BUNDLE; moduleType != expectedModuleType {
			t.Errorf("Network stack component (%v) module-type match failed! got:%v, want:%v", tc.key, moduleType, expectedModuleType)
		}

		storageSide := testhelper.ComponentStorageSide(t, dut, name)
		if _, ok := validStorageSides[storageSide]; ok {
			// Storage side needs to be unique for each network stack component. Remove the current
			// side from valid storage sides map.
			delete(validStorageSides, storageSide)
		} else {
			t.Errorf("Invalid storage-side for network stack component (%v)! got:%v", tc.key, storageSide)
		}
	}
}

func TestGetChassisDefaultMacAddress(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("0bbc650c-d1a7-42d4-b2a3-e19a4336366a").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	name := "chassis"
	baseMacAddress := testhelper.ComponentChassisBaseMacAddress(t, dut, name)
	if _, err := net.ParseMAC(baseMacAddress); err != nil {
		t.Errorf("Invalid base-mac-address format received for chassis! got:%v", baseMacAddress)
	}

	poolSize := testhelper.ComponentChassisMacAddressPoolSize(t, dut, name)
	if !(poolSize >= 1) {
		t.Errorf("Chassis component pool size match failed! got:%v, want:(value >= 1)", poolSize)
	}
}

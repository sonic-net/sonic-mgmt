package system_paths_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"github.com/pkg/errors"

	syspb "github.com/openconfig/gnoi/system"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func verifyAddress(address string, addresses []string) error {
	for _, addr := range addresses {
		if addr == address {
			return nil
		}
	}
	return errors.New("unknown address")
}

func TestGetRemoteServerAddressInfo(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("c2873412-1016-4c89-9e59-79fcfec642bb").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	logInfo, err := testhelper.LoggingServerAddressesForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch remote server logging info: %v", err)
	}

	// Collect remote server addresses.
	foundAddresses := gnmi.GetAll(t, dut, gnmi.OC().System().Logging().RemoteServerAny().Host().State())

	// Determine if configured addresses are IPv4 or IPv6.  We are only allowed to have one or the other.
	hasIpv4, hasIpv6 := false, false
	for _, addr := range foundAddresses {
		if err := verifyAddress(addr, logInfo.IPv4RemoteAddresses); err == nil {
			hasIpv4 = true
		}
		if err := verifyAddress(addr, logInfo.IPv6RemoteAddresses); err == nil {
			hasIpv6 = true
		}
	}

	if !hasIpv4 && !hasIpv6 {
		t.Fatalf("Remote server addresses do not match device logging server addresses: got: %v vs want: %v or want: %v ", strings.Join(foundAddresses, ", "), strings.Join(logInfo.IPv4RemoteAddresses, ", "), strings.Join(logInfo.IPv6RemoteAddresses, ", "))
	}
	if hasIpv4 && hasIpv6 {
		t.Fatalf("Remote server addresses are not expected to mix IPv4 and IPv6 addresses: got: %v", strings.Join(foundAddresses, ", "))
	}

	addresses := logInfo.IPv4RemoteAddresses
	if hasIpv6 {
		addresses = logInfo.IPv6RemoteAddresses
	}

	// Addresses configured may only be what device configuration allows.
	if foundLen, addressLen := len(foundAddresses), len(addresses); foundLen != addressLen {
		t.Errorf("Unexpected number of remote logging server addresses: %v (want %v).", foundLen, addressLen)
	}

	addressSet := make(map[string]bool)
	for _, addr := range foundAddresses {
		addressSet[addr] = true
	}
	// Addresses may not be repeated.
	if setLen, foundLen := len(addressSet), len(foundAddresses); setLen != foundLen {
		t.Errorf("Remote logging addresses are not unique: %v", foundAddresses)
	}

	// Addresses configured may only be what device configuration allows.
	for _, addr := range foundAddresses {
		if err := verifyAddress(addr, addresses); err != nil {
			t.Errorf("Remote logging address is unsupported: %v", addr)
		}
	}

	// Check that state host value matches the rest of the path.
	for _, addr := range foundAddresses {
		if readAddress := gnmi.Get(t, dut, gnmi.OC().System().Logging().RemoteServer(addr).Host().State()); readAddress != addr {
			t.Errorf("Remote logging host address does not match path: %v vs %v", readAddress, addr)
		}
	}
}

func TestGetCurrentDateAndTime(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("8ec03425-b9ab-4e13-8b01-1564b5043d68").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	t1 := time.Now()
	time.Sleep(1 * time.Second)
	dutTime, err := time.Parse(time.RFC3339, gnmi.Get(t, dut, gnmi.OC().System().CurrentDatetime().State()))
	if err != nil {
		t.Fatalf("Failed to parse DUT time: %v", err)
	}
	t2 := time.Now()

	// Time reported by DUT should be between the time the request was sent and received.
	if dutTime.Before(t1) || dutTime.After(t2) {
		t.Errorf("Time comparison failed! got:%v, want:(greater than:%v, less than:%v)", dutTime, t1, t2)
	}
}

func TestGetBootTime(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("c2bcb460-e79a-4ae2-9a74-d1b3d6ec62ae").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// boot-time should be the same before rebooting switch. We give a 1 second buffer to account for
	// jitter in boot-time calculation.
	want := gnmi.Get(t, dut, gnmi.OC().System().BootTime().State())
	time.Sleep(5 * time.Second)
	sec := uint64(time.Second.Nanoseconds())
	if got := gnmi.Get(t, dut, gnmi.OC().System().BootTime().State()); got < want-sec || got > want+sec {
		t.Errorf("boot-time comparison before reboot failed! got:%v, want:%v(+-1s)", got, want)
	}

	waitTime, err := testhelper.RebootTimeForDevice(t, dut)
	if err != nil {
		t.Fatalf("Unable to get reboot wait time: %v", err)
	}
	params := testhelper.NewRebootParams().WithWaitTime(waitTime).WithCheckInterval(30 * time.Second).WithRequest(syspb.RebootMethod_COLD)
	if err := testhelper.Reboot(t, dut, params); err != nil {
		t.Fatalf("Failed to reboot DUT: %v", err)
	}

	// boot-time should be later than the previous boot-time after rebooting switch.
	if got := gnmi.Get(t, dut, gnmi.OC().System().BootTime().State()); got <= want {
		t.Errorf("boot-time comparison after reboot failed! got:%v, want:(greater than)%v", got, want)
	}
}

func TestGetHostname(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("01c119ae-2550-4949-8fd7-3605b8d2981c").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	hostname := gnmi.Get(t, dut, gnmi.OC().System().Hostname().State())
	if len(hostname) == 0 || len(hostname) > 253 {
		t.Errorf("Invalid hostname length! got:%v, want:(0-253)", len(hostname))
	}
	if hostname != dut.Name() {
		t.Errorf("Hostname match failed! got:%v, want:%v", hostname, dut.Name())
	}
}

func TestConfigMetaData(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("366f4520-79f7-49ac-a67d-c53b48b11535").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Perform an initial config push on config-meta-data path.
	// TODO: Remove this step when default config push is available.
	testhelper.ReplaceConfigMetaData(t, dut, "initial metadata")

	origMetaData := testhelper.SystemConfigMetaData(t, dut)
	if len(origMetaData) == 0 {
		t.Error("Invalid initial metadata length! got:0, want:(greater than) 0")
	}
	// Configure a different value of at config-meta-data path.
	newMetaData := "test1"
	if newMetaData == origMetaData {
		newMetaData = "test2"
	}

	testhelper.ReplaceConfigMetaData(t, dut, newMetaData)

	if got, want := testhelper.SystemConfigMetaData(t, dut), newMetaData; got != want {
		t.Errorf("Invalid value for config-meta-data state path! got:%v, want:%v", got, want)
	}
	if got, want := testhelper.SystemConfigMetaDataFromConfig(t, dut), newMetaData; got != want {
		t.Errorf("Invalid value for config-meta-data config path! got:%v, want:%v", got, want)
	}
}

func TestCPUIndexes(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("093c4411-c748-4b7c-bee7-fd73b8c2a473").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	cpuInfo, err := testhelper.CPUInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch CPU information: %v", err)
	}

	// Convert index in expected CPU information to System_Cpu_Index_Union type since this
	// type will be returned in the GET response by the switch.
	wantIndexes := make(map[oc.System_Cpu_Index_Union]bool)
	for _, cpu := range cpuInfo {
		index, err := (&oc.System_Cpu{}).To_System_Cpu_Index_Union(cpu.GetIndex())
		if err != nil {
			t.Fatalf("To_System_Cpu_Index_Union() failed for index:%v (%v)", cpu.GetIndex(), err)
		}
		wantIndexes[index] = true
	}

	gotIndexes := make(map[oc.System_Cpu_Index_Union]bool)
	for i, info := range gnmi.GetAll(t, dut, gnmi.OC().System().CpuAny().State()) {
		if info.Index == nil {
			t.Errorf("CPU index not present in information iteration %v", i)
			continue
		}
		gotIndexes[info.GetIndex()] = true
	}

	if !cmp.Equal(wantIndexes, gotIndexes) {
		t.Errorf("CPU index match failed! (-want +got):%v", cmp.Diff(wantIndexes, gotIndexes))
	}
}

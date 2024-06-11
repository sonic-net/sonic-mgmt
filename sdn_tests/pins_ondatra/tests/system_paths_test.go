package system_paths_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	log "github.com/golang/glog"
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

func TestCPUUsage(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("4806f97b-1c4e-4763-a9e3-58671bda144a").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	cpuInfo, err := testhelper.CPUInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch CPU information: %v", err)
	}

	wantUsage := make(map[oc.System_Cpu_Index_Union]uint8)
	for _, cpu := range cpuInfo {
		index, err := (&oc.System_Cpu{}).To_System_Cpu_Index_Union(cpu.GetIndex())
		if err != nil {
			t.Fatalf("To_System_Cpu_Index_Union() failed for index:%v (%v)", cpu.GetIndex(), err)
		}
		wantUsage[index] = cpu.GetMaxAverageUsage()
	}

	gotInfo := gnmi.GetAll(t, dut, gnmi.OC().System().CpuAny().State())
	if len(gotInfo) != len(wantUsage) {
		t.Errorf("Invalid number of CPU indexes received from switch! got:%v, want:%v", len(gotInfo), len(wantUsage))
	}

	// Fetch the average utilization for each CPU for 2 minutes. In each iteration, validate
	// that the utilization is less than the specified threshold. Also, store the cumulative
	// utilization for each CPU. At the end of 2 minutes, validate that the cumulative
	// utilization for each CPU is non-zero since it is highly unlikely that a CPU is not
	// being utilized during this entire time interval.
	waitTime := 2 * time.Minute
	interval := 10 * time.Second
	cumulativeUsage := make(map[oc.System_Cpu_Index_Union]int)
	log.Infof("Fetching average CPU utilization in %v intervals for %v", interval, waitTime)
	for timeout := time.Now().Add(waitTime); time.Now().Before(timeout); {
		log.Info("========== CPU average usage stats ==========")
		for i, info := range gotInfo {
			if info.Index == nil {
				t.Errorf("CPU index not present in information iteration %v", i)
				continue
			}

			index := info.GetIndex()
			if _, ok := wantUsage[index]; !ok {
				t.Errorf("Invalid index:%v received from DUT", index)
				continue
			}

			got := gnmi.Get(t, dut, gnmi.OC().System().Cpu(index).Total().Avg().State())
			if wantUsage[index] != 0 && got > wantUsage[index] {
				t.Errorf("CPU (index:%v) average usage validation failed! got:%v, want:<%v", index, got, wantUsage[index])
			}
			log.Infof("CPU (index:%v): %v", index, got)
			cumulativeUsage[index] += int(got)
		}

		time.Sleep(interval)
	}

	for i, u := range cumulativeUsage {
		if u == 0 {
			t.Errorf("CPU (index:%v) cumulative average got:0, want:>0", i)
		}
	}

}

func TestCPUInterval(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("534f595e-06b6-434c-b7cb-20d856efacdb").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	cpuInfo, err := testhelper.CPUInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch CPU information: %v", err)
	}

	wantIndexes := make(map[oc.System_Cpu_Index_Union]bool)
	for _, cpu := range cpuInfo {
		index, err := (&oc.System_Cpu{}).To_System_Cpu_Index_Union(cpu.GetIndex())
		if err != nil {
			t.Fatalf("To_System_Cpu_Index_Union() failed for index:%v (%v)", cpu.GetIndex(), err)
		}
		wantIndexes[index] = true
	}

	gotInfo := gnmi.GetAll(t, dut, gnmi.OC().System().CpuAny().State())
	for i, info := range gotInfo {
		if info.Index == nil {
			t.Errorf("CPU index not present in information iteration %v", i)
			continue
		}

		index := info.GetIndex()
		if _, ok := wantIndexes[index]; !ok {
			t.Errorf("Invalid index:%v received from DUT", index)
			continue
		}
		if got := gnmi.Get(t, dut, gnmi.OC().System().Cpu(index).Total().Interval().State()); got == 0 {
			t.Errorf("CPU (index:%v) interval validation failed! got:%v, want:>0", index, got)
		}
	}

	if len(gotInfo) != len(wantIndexes) {
		t.Errorf("Invalid number of CPU indexes received from switch! got:%v, want:%v", len(gotInfo), len(wantIndexes))
	}
}

// This method performs validations on process information leafs.
// It returns whether the validations need to be retried along with the error
// encountered while performing the validations.
// The condition for retry is that there is a missing leaf for the PID. If the
// leaf validation itself fails, the API returns retry = false along with the
// errors encountered.
func validateProcessInformation(procInfo *oc.System_Process, bootTime uint64, systemMemory uint64) (bool, error) {
	var err error
	infoMissing := false
	validationFailed := false
	pid := procInfo.GetPid()

	processString := func() string {
		name := procInfo.GetName()
		if name == "" {
			name = "<empty name>"
		}
		return fmt.Sprintf("%s (pid:%d)", name, pid)
	}

	if procInfo.CpuUtilization == nil {
		infoMissing = true
		err = testhelper.WrapError(err, "Invalid cpu-utilization for %v! got:<nil>, want:range(0-100)", processString())
	} else if got := procInfo.GetCpuUtilization(); got > 100 {
		// Not checking for UMF default value since actual CPU utilization
		// of the process can be 0.
		validationFailed = true
		err = testhelper.WrapError(err, "Invalid cpu-utilization for %v! got:%v, want:range(0-100)", processString())
	}

	if procInfo.MemoryUsage == nil {
		infoMissing = true
		err = testhelper.WrapError(err, "Invalid memory-usage for %v! got:<nil>, want:(<=)%v", processString(), systemMemory)
	} else if got := procInfo.GetMemoryUsage(); got > systemMemory {
		// Not checking for UMF default value since actual memory usage
		// of the process can be 0.
		validationFailed = true
		err = testhelper.WrapError(err, "Invalid memory-usage for %v! got:%v, want:(<=)%v", processString(), got, systemMemory)
	}

	if procInfo.StartTime == nil {
		infoMissing = true
		err = testhelper.WrapError(err, "Invalid start-time for %v! got:<nil>, want:(>=)%v", processString(), bootTime)
	} else {
		got := procInfo.GetStartTime()
		if got == 0 {
			// UMF sends 0 by default. start-time of a process cannot be 0.
			// This indicates missing DB information.
			infoMissing = true
			err = testhelper.WrapError(err, "Invalid start-time for %v! got:%v, want:(>=)%v", processString(), got, bootTime)
		} else if got < bootTime {
			validationFailed = true
			err = testhelper.WrapError(err, "Invalid start-time for %v! got:%v, want:(>=)%v", processString(), got, bootTime)
		}
	}

	if procInfo.Name == nil {
		infoMissing = true
		err = testhelper.WrapError(err, "Invalid name for pid:%v! got:<nil>, want:<non-empty>", pid)
	} else if procInfo.GetName() == "" {
		// UMF sends empty name by default. name of a process cannot be empty.
		// This indicates missing DB information.
		infoMissing = true
		err = testhelper.WrapError(err, "Invalid name for pid:%v! got:<empty>, want:<non-empty>", pid)
	}

	// CPU usage time might not be present since the process might be ephemeral. In such cases,
	// only log that the information is not present.
	if procInfo.CpuUsageUser == nil {
		log.Infof("cpu-usage-user not reported for %v", processString())
	}
	if procInfo.CpuUsageSystem == nil {
		log.Infof("cpu-usage-system not reported for %v", processString())
	}

	if validationFailed {
		// Don't retry if validation failed for a particular leaf.
		return false, err
	}

	// None of the validations failed, so retry if information for a leaf
	// is missing.
	return infoMissing, err
}

func TestMemoryStatistics(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("d2f4917b-3813-4e81-b195-8f6b9222d615").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	expectedInfo, err := testhelper.MemoryInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch memory information for device: %v", err)
	}
	info := gnmi.Get(t, dut, gnmi.OC().System().Memory().State())

	if info.Physical == nil {
		t.Error("Physical memory information not received from DUT")
	} else {
		// Physical memory value returned by the switch might not be an exact match.
		// Provide 1GB error margin.
		errMargin := uint64(1073741824)
		if got, want := info.GetPhysical(), expectedInfo.GetPhysical(); got > want || want-got > errMargin {
			t.Errorf("Physical memory validation failed! got:%v, want:%v (error margin: -%v)", got, want, errMargin)
		}
	}

	if info.Free == nil {
		t.Error("Free memory information not received from DUT")
	} else {
		if got, want := info.GetFree(), info.GetPhysical(); got > want {
			t.Errorf("Free memory (%v) more than physical memory (%v)", got, want)
		}
		if expectedInfo.GetFreeThreshold() != 0 {
			// Free memory threshold specified for the device.
			if got, want := info.GetFree(), expectedInfo.GetFreeThreshold(); got < want {
				t.Errorf("Free memory threshold validation failed! got:%v, want:>=%v", got, want)
			}
		}
	}

	if info.Used == nil {
		t.Error("Used memory information not received from DUT")
	} else {
		if got, want := info.GetUsed(), info.GetPhysical(); got > want {
			t.Errorf("Used memory (%v) more than physical memory (%v)", got, want)
		}
		if expectedInfo.GetUsedThreshold() != 0 {
			// Used memory threshold specified for the device.
			if got, want := info.GetUsed(), expectedInfo.GetUsedThreshold(); got > want {
				t.Errorf("Used memory threshold validation failed! got:%v, want:<=%v", got, want)
			}
		}
	}
}

func TestMemoryErrorStatistics(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("6300ee99-ac15-4913-a8a8-9231bb92a498").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	expectedInfo, err := testhelper.MemoryInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch memory information for device: %v", err)
	}
	info := gnmi.Get(t, dut, gnmi.OC().System().Memory().Counters().State())

	if info.CorrectableEccErrors == nil {
		t.Errorf("correctable-ecc-errors information not received from DUT")
	} else {
		if got, want := info.GetCorrectableEccErrors(), expectedInfo.GetCorrectableEccErrorThreshold(); want != 0 && got > want {
			t.Errorf("correctable-ecc-errors threshold exceeded! got:%v, want:<=%v", got, want)
		}
	}

	if info.UncorrectableEccErrors == nil {
		t.Errorf("uncorrectable-ecc-errors information not received from DUT")
	} else {
		if got := info.GetUncorrectableEccErrors(); got != 0 {
			t.Errorf("uncorrectable-ecc-errors detected on the DUT! got:%v, want:0", got)
		}
	}
}

func TestNTPServerInformation(t *testing.T) {
	dut := ondatra.DUT(t, "DUT")

	tests := []struct {
		name                string
		uuid                string
		checkAllInformation bool
	}{
		{
			name: "TestServerAddress",
			uuid: "a0cd293a-0a26-4b2a-bf8f-3819e885ed1a",
		},
		{
			name:                "TestServerInfo",
			uuid:                "0b83e93f-5d85-4100-ba81-a5f1af058763",
			checkAllInformation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			expectedInfo, err := testhelper.NTPServerInfoForDevice(t, dut)
			if err != nil {
				t.Fatalf("Failed to fetch NTP server information for device: %v", err)
			}

			ntp := gnmi.Get(t, dut, gnmi.OC().System().Ntp().State())
			if ntp == nil {
				t.Fatalf("No NTP information received from DUT")
			}
			serverInfo := ntp.Server

			// Each NTP server IP address is returned separately from the DUT.
			// Therefore, all expected IP addresses need to be aggregated before
			// comparing with the received information.
			expectedServerNum := 0
			for _, info := range expectedInfo {
				expectedServerNum += len(info.GetIPv4Address()) + len(info.GetIPv6Address())
			}

			if got, want := len(serverInfo), expectedServerNum; got != want {
				t.Errorf("Invalid number of NTP servers! got:%v, want:%v", got, want)
			}

			for _, info := range expectedInfo {
				// For each expected NTP server, fetch the IPv4 and IPv6 address from the
				// gNMI response and perform validations.
				ipv4Reachable := false
				ipv6Reachable := false
				expectedAddresses := []struct {
					addresses []string
					isIPv4    bool
				}{
					{
						addresses: info.GetIPv4Address(),
						isIPv4:    true,
					},
					{
						addresses: info.GetIPv6Address(),
					},
				}
				for _, e := range expectedAddresses {
					for _, address := range e.addresses {
						// Ensure that the server address is present in the gNMI response.
						log.Infof("Validating NTP server: %s", address)
						if _, ok := serverInfo[address]; !ok {
							t.Errorf("%v NTP server not reported by DUT", address)
							continue
						}
						server := serverInfo[address]
						if got, want := server.GetAddress(), address; got != want {
							t.Errorf("%v NTP server has invalid address field! got:%v, want:%v", address, got, want)
						}

						// Only perform additional checks if checkAllInformation is set.
						if !tt.checkAllInformation {
							continue
						}

						// Do not perform value checks for unreachable servers.
						// Only ensure that fields are present in the response.
						checkValue := false

						if server.Stratum == nil {
							t.Errorf("%v NTP server doesn't have stratum information", address)
						} else if checkValue {
							if got, want := server.GetStratum(), info.GetStratumThreshold(); want != 0 && got > want {
								t.Errorf("%v NTP server has invalid stratum field! got:%v, want:<=%v", address, got, want)
							}
						}

						if server.RootDelay == nil {
							t.Errorf("%v NTP server doesn't have root-delay information", address)
						} else if checkValue {
							if got := server.GetRootDelay(); got == 0 {
								t.Errorf("%v NTP server has invalid root-delay field! got:%v, want:>0", address, got)
							}
						}

						if server.PollInterval == nil {
							t.Errorf("%v NTP server doesn't have poll-interval information", address)
						} else {
							// Poll interval value should always be checked since the NTP
							// client must poll the server at non-zero intervals.
							if got := server.GetPollInterval(); got == 0 {
								t.Errorf("%v NTP server has invalid poll-interval field! got:%v, want:>0", address, got)
							}
						}

						if server.RootDispersion == nil {
							t.Errorf("%v NTP server doesn't have root-dispersion information", address)
						} else if checkValue {
							if got := server.GetRootDispersion(); got == 0 {
								t.Errorf("%v NTP server has invalid root-dispersion field! got:%v, want:>0", address, got)
							}
						}
					}
				}

				// Server should be reachable via an IPv4 or IPv6 address.
				if tt.checkAllInformation && !ipv4Reachable && !ipv6Reachable {
					ipAddresses := append(info.GetIPv4Address(), info.GetIPv6Address()...)
					t.Errorf("NTP server with IP addresses: %v is not reachable", strings.Join(ipAddresses, ","))
				}
			}
		})
	}
}

func TestMountPointsInformation(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("c0cf81e1-e99d-4b57-b273-9fe87c713881").Teardown(t)

	dut := ondatra.DUT(t, "DUT")

	mountPoints, err := testhelper.MountPointsInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch mount points information for device: %v", err)
	}

	// Validate that DUT returns at least the required number of mount points.
	if got := gnmi.GetAll(t, dut, gnmi.OC().System().MountPointAny().State()); len(got) < len(mountPoints) {
		t.Errorf("Invalid number of mount points! got:%v, want:>=%v", len(got), len(mountPoints))
	}

	for _, mp := range mountPoints {
		name := mp.GetName()
		info := gnmi.Get(t, dut, gnmi.OC().System().MountPoint(name).State())

		if info.Size == nil {
			t.Errorf("%v missing size leaf", name)
		} else if info.GetSize() == 0 {
			t.Errorf("%v has invalid size! got:0, want:>0", name)
		}

		if info.Available == nil {
			t.Errorf("%v missing available leaf", name)
		}

		if info.Size != nil && info.Available != nil {
			if size, available := info.GetSize(), info.GetAvailable(); available > size {
				t.Errorf("available space:%v exceeds size:%v for mount point %v", available, size, name)
			}
		}
	}
}

func printProcessStatistics(t *testing.T, stats map[uint64]oc.System_Process) {
	logString := "\n***************************************\n"
	logString += "\tProcess Statistics"
	logString += "\n***************************************\n"
	for pid, info := range stats {
		logString += fmt.Sprintf("Process: %s\n", info.GetName())
		logString += fmt.Sprintf("PID: %d\n", pid)
		startTime := info.GetStartTime()
		// Nanoseconds to seconds.
		divider := uint64(1000000000)
		logString += fmt.Sprintf("Start Time: %d (%s)\n", startTime, time.Unix(int64(startTime/divider), int64(startTime%divider)))
		m := info.GetMemoryUsage() / 1000000
		suffix := "MB"
		if m > 1000 {
			m = m / 1000
			suffix = "GB"
		}
		logString += fmt.Sprintf("Memory Usage: %d bytes (%d %s)\n", info.GetMemoryUsage(), m, suffix)
		logString += fmt.Sprintf("Memory Utilization: %d%%\n", info.GetMemoryUtilization())
		logString += fmt.Sprintf("CPU Utilization: %d%%\n", info.GetCpuUtilization())
		logString += "--------------------------------------------------------------------\n"
	}
	t.Log(logString)
}

// This is a GPINs-specific test since it makes assumptions about the
// functionality of systemstatsd back-end.
func TestProcessStatistics(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("dc958005-d45b-429d-9ee1-c14cc1eefcf2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	info := gnmi.GetAll(t, dut, gnmi.OC().System().ProcessAny().State())
	if len(info) == 0 {
		t.Fatalf("Invalid number of PIDs! got:0, want:>=1")
	}
	bootTime := gnmi.Get(t, dut, gnmi.OC().System().BootTime().State())
	systemMemory := gnmi.Get(t, dut, gnmi.OC().System().Memory().Physical().State())

	// Systemstatsd updates process attributes one-by-one in the DB in the
	// following order:
	// cpu-utilization, memory-usage, start-time, name.
	// If any of the above attributes are empty or not present, retry fetching
	// information for that process. If that also fails, only then declare the
	// test as failure.
	var retryPID []uint64
	stats := make(map[uint64]oc.System_Process)
	for _, procInfo := range info {
		pid := procInfo.GetPid()
		if pid == 0 {
			t.Errorf("Invalid PID value! got:0, want:>=1")
			continue
		}
		stats[pid] = *procInfo

		retry, err := validateProcessInformation(procInfo, bootTime, systemMemory)
		if retry {
			log.Infof("Adding pid:%v to retry list. Failures seen:\n %v", pid, err)
			retryPID = append(retryPID, pid)
		} else if err != nil {
			// At least one validation failed.
			t.Error(err)
		}
	}

	time.Sleep(1 * time.Second)
	for _, pid := range retryPID {
		log.Infof("Retrying information validation for pid:%v", pid)
		procInfo := gnmi.Get(t, dut, gnmi.OC().System().Process(pid).State())
		if _, err := validateProcessInformation(procInfo, bootTime, systemMemory); err != nil {
			t.Errorf("Validation failed for pid:%v\n %v", pid, err)
		}
		stats[pid] = *procInfo
	}

	printProcessStatistics(t, stats)
}

func generateLabel(existingLabelsSubtree []*testhelper.System_FeatureLabel) (label uint32, ok bool) {
	currLabels := map[uint32]bool{}
	for _, val := range existingLabelsSubtree {
		currLabels[val.GetLabel()] = true
	}
	// Loop (for a maximum of 100 times) until a label is generated that is not an existing label on
	// the switch. Exit if unable to generate a suitable label.
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 100; i++ {
		label = rand.Uint32()
		if !currLabels[label] {
			return label, true
		}
	}
	return label, false
}

func TestFeatureLabels(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("b5c1a559-21b6-4fa0-b5ff-1f15080b7b0f").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Get the existing feature-labels tree.
	existingLabelsSubtree := testhelper.SystemFeatureLabels(t, dut)

	// Generate a unique label not already configured on the switch.
	label, labelGenerated := generateLabel(existingLabelsSubtree)
	if !labelGenerated {
		t.Fatalf("Couldn't generate a new label from feature-labels: %v", existingLabelsSubtree)
	}

	featureLabel := testhelper.CreateFeatureLabel(label)
	gnmi.Replace(t, dut, testhelper.SystemFeatureLabelPath(gnmi.OC().System(), label).Config(), featureLabel)
	testhelper.AwaitSystemFeatureLabel(t, dut, 5*time.Second, featureLabel)

	defer func() {
		// Remove the configured feature-label after the test.
		gnmi.Delete(t, dut, testhelper.SystemFeatureLabelPath(gnmi.OC().System(), label).Config())
		labelsSubtree := testhelper.SystemFeatureLabels(t, dut)
		if len(labelsSubtree) != len(existingLabelsSubtree) {
			t.Errorf("Incorrect number of feature-labels found after FeatureLabel(%v).Delete; got:%v, want:%v", label, len(labelsSubtree), len(existingLabelsSubtree))
		}
		for _, val := range labelsSubtree {
			if val.GetLabel() == label {
				t.Errorf("Path did not get deleted; got:%v, want:<nil>", label)
			}
		}
	}()

	// Get the new feature-labels tree after Set Replace.
	newLabelsSubtree := testhelper.SystemFeatureLabels(t, dut)
	if got, want := len(newLabelsSubtree), len(existingLabelsSubtree)+1; got != want {
		t.Fatalf("Incorrect number of feature-labels found after FeatureLabel(%v).Replace; got:%v, want:%v", label, got, want)
	}

	// Verify that the new feature-label is present in the feature-labels subtree.
	labelFound := false
	for _, val := range newLabelsSubtree {
		if val.GetLabel() == label {
			labelFound = true
			break
		}
	}
	if !labelFound {
		t.Fatalf("Couldn't find configured label: %v in feature-labels: %v", label, newLabelsSubtree)
	}

	// Verify the GET response for the feature-label state and config leaf paths.
	if got, want := testhelper.SystemFeatureLabel(t, dut, label).GetLabel(), label; got != want {
		t.Errorf("gnmi.Get(t, dut, gnmi.OC().System().FeatureLabel(label).State()).GetLabel() got:%v, want:%v", got, want)
	}
	if got, want := testhelper.SystemFeatureLabelFromConfig(t, dut, label).GetLabel(), label; got != want {
		t.Errorf("gnmi.GetConfig(t, dut, gnmi.OC().System().FeatureLabel(label).Config()).GetLabel() got:%v, want:%v", got, want)
	}
}

package platforms_hardware_component_test

import (
        "regexp"
	"reflect"
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

const awaitTime = 5 * time.Second

func verifyRegexMatch(r string, s string) error {
        match, err := regexp.MatchString(r, s)
        if err != nil {
                return err
        }
        if !match {
                return errors.Errorf("regex match failed, got:%v, want(regex):%v", s, r)
        }

        return nil
}

func TestMain(m *testing.M) {
        ondatra.RunTests(m, pinsbind.New)
}

// Integrated Circuit tests.
func TestGetICInformation(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("758cf6e4-fac4-4d1c-ba6b-3bf399a66b80").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        ics, err := testhelper.ICInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch integrated-circuit info: %v", err)
        }

        for _, ic := range ics {
                name := ic.GetName()
                componentPath := gnmi.OC().Component(name)

                if got, want := gnmi.Get(t, dut, componentPath.Parent().State()), "chassis"; got != want {
                        t.Errorf("Integrated circuit component (%v) parent match failed! got:%v, want:%v", name, got, want)
                }

                if got, want := gnmi.Get(t, dut, componentPath.Type().State()), oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_INTEGRATED_CIRCUIT; got != want {
                        t.Errorf("Integrated circuit component (%v) type match failed! got:%v, want:%v", name, got, want)
                }
        }
}

func TestGetICErrorInformation(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("bb7e3980-2e6d-4a02-bb42-1872b16d96f7").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        ics, err := testhelper.ICInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch integrated-circuit info: %v", err)
        }

        for _, ic := range ics {
                name := ic.GetName()
                info := gnmi.Get(t, dut, gnmi.OC().Component(name).IntegratedCircuit().Memory().State())

                if info.CorrectedParityErrors == nil {
                        t.Errorf("%v doesn't have corrected-parity-errors information", name)
                }
                if info.TotalParityErrors == nil {
                        t.Errorf("%v doesn't have total-parity-errors information", name)
                }
                // If the error information is not present, they will be initialized to 0.
                correctedErrors := info.GetCorrectedParityErrors()
                totalErrors := info.GetTotalParityErrors()

                // Corrected parity errors should be within defined threshold.
                if got, want := correctedErrors, ic.GetCorrectedParityErrorsThreshold(); want != 0 && got > want {
                        t.Errorf("%v corrected-parity-errors threshold exceeded! got:%v, want:<=%v", name, got, want)
                }
                // Corrected parity errors cannot be more than the total parity errors.
                if correctedErrors > totalErrors {
                        t.Errorf("%v has more corrected-parity-errors:%v than total-parity-errors:%v", name, correctedErrors, totalErrors)
                }
                // IC shouldn't have uncorrected errors.
                if totalErrors > correctedErrors {
                        t.Errorf("%v has uncorrected-parity-errors:%v, want:0", name, totalErrors-correctedErrors)
                }
        }
}

func TestSetValidICName(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("a255135d-66be-43e8-be05-46e746c033c2").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        ics, err := testhelper.ICInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch integrated-circuit info: %v", err)
        }

        for _, ic := range ics {
                name := ic.GetName()
                componentPath := gnmi.OC().Component(name)

                gnmi.Replace(t, dut, componentPath.Name().Config(), name)
                gnmi.Await(t, dut, componentPath.Name().State(), awaitTime, name)

                fullyQualifiedName := "abc.def.test.com"
                testhelper.ReplaceFullyQualifiedName(t, dut, name, fullyQualifiedName)
                testhelper.AwaitFullyQualifiedName(t, dut, name, awaitTime, fullyQualifiedName)
        }
}

func TestSetInvalidICName(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("6632a6dc-eec1-4d8f-9ccb-63b380dc841d").Teardown(t)

        invalidNames := []string{
                "integrated_circuit1234",
                "integrated_circuitX",
                "invalid_name",
        }

        dut := ondatra.DUT(t, "DUT")
        ics, err := testhelper.ICInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch integrated-circuit info: %v", err)
        }

        for _, ic := range ics {
                name := ic.GetName()
                configPath := gnmi.OC().Component(name).Name()
                statePath := gnmi.OC().Component(name).Name()

                // Set config path so that the corresponding Get() works later on in the test.
                gnmi.Replace(t, dut, configPath.Config(), name)
                gnmi.Await(t, dut, statePath.State(), awaitTime, name)

                // Configure invalid name values on the DUT.
                for _, invalid := range invalidNames {
                        testt.ExpectFatal(t, func(t testing.TB) {
                                gnmi.Replace(t, dut, configPath.Config(), invalid)
                        })
                        // Verify that config path doesn't reflect the invalid name.
                        if got, want := gnmi.Get(t, dut, configPath.Config()), name; got != want {
                                t.Errorf("Invalid (config) name on %v! got:%v, want:%v", name, got, want)
                        }
                        // Verify that state path doesn't reflect the invalid name.
                        if got, want := gnmi.Get(t, dut, statePath.State()), name; got != want {
                                t.Errorf("Invalid (state) name on %v! got:%v, want:%v", name, got, want)
                        }
                }
        }
}

func TestSetNodeID(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("7165b086-5d8f-4283-9e4c-aa4a44fe6fbd").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        ics, err := testhelper.ICInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch integrated-circuit info: %v", err)
        }

        for _, ic := range ics {
                name := ic.GetName()

                nodeID := uint64(12345678)
                gnmi.Replace(t, dut, gnmi.OC().Component(name).IntegratedCircuit().NodeId().Config(), nodeID)
                gnmi.Await(t, dut, gnmi.OC().Component(name).IntegratedCircuit().NodeId().State(), awaitTime, nodeID)
        }
}

func TestPersistenceAfterReboot(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("0e429a29-d3b1-486b-b3d2-3ca48a9f0c35").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        ics, err := testhelper.ICInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch integrated-circuit info: %v", err)
        }

        fullyQualifiedName := "abc.def.test.com"
        nodeID := uint64(12345678)

        t.Log("Configuring config paths before reboot")
        for _, ic := range ics {
                name := ic.GetName()
                componentPath := gnmi.OC().Component(name)

                // Configure config paths and verify corresponding state paths.
                gnmi.Replace(t, dut, componentPath.Name().Config(), name)
                testhelper.ReplaceFullyQualifiedName(t, dut, name, fullyQualifiedName)
                testhelper.ReplaceComponentIntegratedCircuitNodeID(t, dut, name, nodeID)
                gnmi.Replace(t, dut, componentPath.IntegratedCircuit().NodeId().Config(), nodeID)
                time.Sleep(awaitTime)

                info := gnmi.Get(t, dut, componentPath.State())
                if got, want := info.GetName(), name; got != want {
                        t.Errorf("name verification failed for %v! got:%v, want:%v", name, got, want)
                }
                if got, want := testhelper.GetFullyQualifiedName(t, dut, name), fullyQualifiedName; got != want {
                        t.Errorf("fully-qualified-name verification failed for %v! got:%v, want:%v", name, got, want)
                }
                if got, want := gnmi.Get(t, dut, componentPath.IntegratedCircuit().NodeId().State()), nodeID; got != want {
                        t.Errorf("node-id verification failed for %v! got:%v, want:%v", name, got, want)
                }
        }

        // Reboot DUT and verify that the state paths reflect pre-reboot values.
        waitTime, err := testhelper.RebootTimeForDevice(t, dut)
        if err != nil {
                t.Fatalf("Unable to get reboot wait time: %v", err)
        }
        params := testhelper.NewRebootParams().WithWaitTime(waitTime).WithCheckInterval(30 * time.Second).WithRequest(syspb.RebootMethod_COLD)
        if err := testhelper.Reboot(t, dut, params); err != nil {
                t.Fatalf("Failed to reboot DUT: %v", err)
        }

        t.Log("Verifying config and state paths after reboot")
        for _, ic := range ics {
                name := ic.GetName()
                componentPath := gnmi.OC().Component(name)

                stateInfo := gnmi.Get(t, dut, componentPath.State())
                if got, want := stateInfo.GetName(), name; got != want {
                        t.Errorf("name state path verification failed for %v! got:%v, want:%v", name, got, want)
                }
                if got, want := testhelper.GetFullyQualifiedName(t, dut, name), fullyQualifiedName; got != want {
                        t.Errorf("fully-qualified-name state path verification failed for %v! got:%v, want:%v", name, got, want)
                }
                if got, want := gnmi.Get(t, dut, componentPath.IntegratedCircuit().NodeId().State()), nodeID; got != want {
                        t.Errorf("node-id state path verification failed for %v! got:%v, want:%v", name, got, want)
                }

                configInfo := gnmi.Get(t, dut, componentPath.Config())
                if got, want := configInfo.GetName(), name; got != want {
                        t.Errorf("name config path verification failed for %v! got:%v, want:%v", name, got, want)
                }
                if got, want := testhelper.GetFullyQualifiedNameFromConfig(t, dut, name), fullyQualifiedName; got != want {
                        t.Errorf("fully-qualified-name config path verification failed for %v! got:%v, want:%v", name, got, want)
                }
                if got, want := gnmi.Get(t, dut, componentPath.IntegratedCircuit().NodeId().Config()), nodeID; got != want {
                        t.Errorf("node-id config path verification failed for %v! got:%v, want:%v", name, got, want)
                }
        }
}

// FPGA tests.
func TestGetFPGAInfo(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("52a71049-40dc-4f2d-b074-4b0f649064f0").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        fpgas, err := testhelper.FPGAInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch FPGA info: %v", err)
        }

        var fpgaResetCounts []uint8
        for _, fpga := range fpgas {
                name := fpga.GetName()
                componentPath := gnmi.OC().Component(name)
                wantType := "FPGA"
                if gotType := testhelper.FPGAType(t, dut, &fpga); gotType != wantType {
                        t.Errorf("%v type match failed! got:%v, want:%v", name, gotType, wantType)
                }

                if mfgName := gnmi.Get(t, dut, componentPath.MfgName().State()); mfgName != fpga.GetMfgName() {
                        t.Errorf("%v manufacturer name match failed! got:%v, want:%v", name, mfgName, fpga.GetMfgName())
                }

                if description := gnmi.Get(t, dut, componentPath.Description().State()); description != fpga.GetDescription() {
                        t.Errorf("%v description match failed! got:%v, want:%v", name, description, fpga.GetDescription())
                }

                if err := verifyRegexMatch(fpga.GetFirmwareVersionRegex(), gnmi.Get(t, dut, componentPath.FirmwareVersion().State())); err != nil {
                        t.Errorf("%v firmware version match failed! %v", name, err)
                }

                resetCauseMap := testhelper.FPGAResetCauseMap(t, dut, &fpga) //fpgaInfo.ResetCause
                if got, want := len(resetCauseMap), fpga.GetResetCauseNum(); got != want {
                        t.Errorf("%v invalid number of reset causes! got:%v, want:%v", name, got, want)
                }
                for index, resetCause := range resetCauseMap {
                        if got, want := resetCause.GetIndex(), index; got != want {
                                t.Errorf("%v reset-cause-index: %v index match failed! got:%v, want:%v", name, index, got, want)
                        }
                        if got := resetCause.GetCause(); got < testhelper.ResetCause_Cause_POWER || got > testhelper.ResetCause_Cause_CPU {
                                t.Errorf("%v reset-cause-index: %v cause match failed! got:%v, want:range(%v-%v)", name, index, got, testhelper.ResetCause_Cause_POWER, testhelper.ResetCause_Cause_CPU)
                        }
                }

                // Need to know current reset count, since after reboot it should be current count + 1.
                fpgaResetCounts = append(fpgaResetCounts, testhelper.FPGAResetCount(t, dut, &fpga))
        }

        // Reboot DUT and verify that the latest reset cause is SOFTWARE.
        waitTime, err := testhelper.RebootTimeForDevice(t, dut)
        if err != nil {
                t.Fatalf("Unable to get reboot wait time: %v", err)
        }
        params := testhelper.NewRebootParams().WithWaitTime(waitTime).WithCheckInterval(30 * time.Second).WithRequest(syspb.RebootMethod_COLD)
        if err := testhelper.Reboot(t, dut, params); err != nil {
                t.Fatalf("Failed to reboot DUT: %v", err)
        }
        // Wait for the switch to update FPGA information.
        time.Sleep(time.Minute)

        for i, fpga := range fpgas {
                name := fpga.GetName()

                if got, want := testhelper.FPGAResetCount(t, dut, &fpga), fpgaResetCounts[i]+1; got != want {
                        t.Errorf("%v latest reset count match failed after reboot! got:%v, want:%v", name, got, want)
                }

                if fpga.GetResetCauseNum() == 0 {
                        // This FPGA doesn't support reset causes.
                        continue
                }
                if got, want := testhelper.FPGAResetCause(t, dut, &fpga, 0), testhelper.ResetCause_Cause_SOFTWARE; got != want {
                        t.Errorf("%v latest reset cause match failed after reboot! got:%v, want:%v", name, got, want)
                }
        }
}

// Temperature sensor tests.
func TestGetTemperatureSensorDefaultInformation(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("b68ca974-590c-4685-9da4-4c344c74a056").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        type sensorInfo struct {
                ocType  oc.E_PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT
                subType string
        }
        sensorInfoMap := map[testhelper.TemperatureSensorType]sensorInfo{
                testhelper.CPUTempSensor: {
                        ocType: oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_CPU,
                },
                testhelper.HeatsinkTempSensor: {
                        ocType:  oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_SENSOR,
                        subType: "HEAT_SINK_TEMPERATURE_SENSOR",
                },
                testhelper.ExhaustTempSensor: {
                        ocType:  oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_SENSOR,
                        subType: "EXHAUST_TEMPERATURE_SENSOR",
                },
                testhelper.InletTempSensor: {
                        ocType:  oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_SENSOR,
                        subType: "INLET_TEMPERATURE_SENSOR",
                },
                testhelper.DimmTempSensor: {
                        ocType:  oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_SENSOR,
                        subType: "DIMM_TEMPERATURE_SENSOR",
                },
        }

        tests := []struct {
                name       string
                sensorType testhelper.TemperatureSensorType
        }{
                {
                        name:       "CPUTemperatureSensorInfo",
                        sensorType: testhelper.CPUTempSensor,
                },
                {
                        name:       "HeatsinkTemperatureSensorInfo",
                        sensorType: testhelper.HeatsinkTempSensor,
                },
                {
                        name:       "ExhaustTemperatureSensorInfo",
                        sensorType: testhelper.ExhaustTempSensor,
                },
                {
                        name:       "InletTemperatureSensorInfo",
                        sensorType: testhelper.InletTempSensor,
                },
                {
                        name:       "DimmTemperatureSensorInfo",
                        sensorType: testhelper.DimmTempSensor,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        expectedInfo, ok := sensorInfoMap[tt.sensorType]
                        if !ok {
                                t.Fatalf("Sensor type: %v not found in expected info map", tt.sensorType)
                        }

                        sensors, err := testhelper.TemperatureSensorInfoForDevice(t, dut, tt.sensorType)
                        if err != nil {
                                t.Fatalf("Failed to fetch temperature info for %v: %v", expectedInfo, err)
                        }

                        for _, sensor := range sensors {
                                name := sensor.GetName()
                                info := gnmi.Get(t, dut, gnmi.OC().Component(name).State())

                                if got, want := info.GetName(), name; got != want {
                                        t.Errorf("%v name match failed! got:%v, want:%v", name, got, want)
                                }
                                if got, want := info.GetParent(), "chassis"; got != want {
                                        t.Errorf("%v parent match failed! got:%v, want:%v", name, got, want)
                                }
                                if got, want := info.GetType(), expectedInfo.ocType; got != want {
                                        t.Errorf("%v type match failed! got:%v, want:%v", name, got, want)
                                }
                                if got, want := info.GetLocation(), sensor.GetLocation(); got != want {
                                        t.Errorf("%v location match failed! got:%v, want:%v", name, got, want)
                                }

                                // Sensor sub-type is not applicable for CPU temperature sensor.
                                if tt.sensorType == testhelper.CPUTempSensor {
                                        continue
                                }

                                if got, want := testhelper.SensorType(t, dut, &sensor), expectedInfo.subType; got != want {
                                        t.Errorf("%v sensor sub-type match failed! got:%v, want:%v", name, got, want)
                                        continue
                                }
                        }

                })
        }
}

func TestGetTemperatureSensorTemperatureInformation(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("294bf647-cff4-47d6-a701-ad9dfe7ff8f3").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        tests := []struct {
                name       string
                sensorType testhelper.TemperatureSensorType
        }{
                {
                        name:       "CPUTemperatureSensorInfo",
                        sensorType: testhelper.CPUTempSensor,
                },
                {
                        name:       "HeatsinkTemperatureSensorInfo",
                        sensorType: testhelper.HeatsinkTempSensor,
                },
                {
                        name:       "ExhaustTemperatureSensorInfo",
                        sensorType: testhelper.ExhaustTempSensor,
                },
                {
                        name:       "InletTemperatureSensorInfo",
                        sensorType: testhelper.InletTempSensor,
                },
                {
                        name:       "DimmTemperatureSensorInfo",
                        sensorType: testhelper.DimmTempSensor,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        sensors, err := testhelper.TemperatureSensorInfoForDevice(t, dut, tt.sensorType)
                        if err != nil {
                                t.Fatalf("Failed to fetch temperature info for sensor type %v: %v", tt.sensorType, err)
                        }

                        for _, sensor := range sensors {
                                name := sensor.GetName()
                                if got, want := gnmi.Get(t, dut, gnmi.OC().Component(name).Temperature().Instant().State()), sensor.GetMaxTemperature(); want != 0 && got > want {
                                        t.Errorf("%v temperature threshold exceeded! got:%v, want:<=%v", name, got, want)
                                }
                        }

                })
        }
}

// Health-indicator test.
func TestSetPortHealthIndicator(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("77865f9c-5919-467f-8be2-19a08d6803f9").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        port, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        values := []testhelper.E_Interface_HealthIndicator{
                testhelper.Interface_HealthIndicator_BAD,
                testhelper.Interface_HealthIndicator_GOOD,
        }
        for _, healthIndicator := range values {
                testhelper.ReplaceHealthIndicator(t, dut, port, healthIndicator)
                testhelper.AwaitHealthIndicator(t, dut, port, 5*time.Second, healthIndicator)
        }
}

// Storage device test.
func TestStorageDeviceInformation(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("b5db258b-2e3f-4880-96dc-db2ac452afe9").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        devices, err := testhelper.StorageDeviceInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch storage devices: %v", err)
        }

        // Removable storage devices may not be present in the switch. This will cause
        // dut.Telemetry().Component(name).Get() API to fail fatally. Instead, fetch the
        // entire component subtree and validate storage device information.
        components := gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().State())

        for _, device := range devices {
                name := device.GetName()

                var info *oc.Component
                for _, component := range components {
                        if component.GetName() == name {
                                info = component
                                break
                        }
                }
                if info == nil {
                        if device.GetIsRemovable() == false {
                                t.Errorf("%v information is missing in DUT", name)
                        } else {
                                t.Logf("Skipping verification for removable storage device %v since it is not present in DUT", name)
                        }
                        continue
                }
                t.Logf("Validating information for storage device: %v", name)

                if info.Name == nil {
                        t.Errorf("%v missing name leaf", name)
                } else {
                        if got, want := info.GetName(), name; got != want {
                                t.Errorf("%v name match failed! got:%v, want:%v", name, got, want)
                        }
                }
                if info.Type == nil {
                        t.Errorf("%v missing type leaf", name)
                } else {
                        if got, want := info.GetType(), oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_STORAGE; got != want {
                                t.Errorf("%v type match failed! got:%v, want:%v", name, got, want)
                        }
                }
                if info.PartNo == nil {
                        t.Errorf("%v missing part-no leaf", name)
                } else if info.GetPartNo() == "" {
                        t.Errorf("%v has empty part-no", name)
                }
                if info.SerialNo == nil {
                        t.Errorf("%v missing serial-no leaf", name)
                } else if info.GetSerialNo() == "" {
                        t.Errorf("%v has empty serial-no", name)
                }

                if info.Removable == nil {
                        t.Errorf("%v missing removable leaf", name)
                } else {
                        if got, want := info.GetRemovable(), device.GetIsRemovable(); got != want {
                                t.Errorf("%v removable match failed! got:%v, want:%v", name, got, want)
                        }
                }

                // Only check io-error information for non-removable storage devices.
                if device.GetIsRemovable() {
                        continue
                }
                if got, want := testhelper.StorageIOErrors(t, dut, &device), device.GetIoErrorsThreshold(); got > want {
                        t.Errorf("%v io-errors threshold exceeded! got:%v, want:<=%v", name, got, want)
                }
        }
}

// Storage device SMART info test.
func TestStorageDeviceSmartInformation(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("c5fe2192-9759-4829-9231-8fdb4ecc4245").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        devices, err := testhelper.StorageDeviceInfoForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch storage devices: %v", err)
        }

        // Removable storage devices may not be present in the switch. This will cause
        // dut.Telemetry().Component(name).Get() API to fail fatally. Instead, fetch the
        // entire component subtree and validate storage device information.
        components := gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().State())

        for _, device := range devices {
                // Only check SMART information for non-removable storage devices.
                if device.GetIsRemovable() {
                        continue
                }

                name := device.GetName()

                var info *oc.Component
                for _, component := range components {
                        if component.GetName() == name {
                                info = component
                                break
                        }
                }
                if info == nil {
                        t.Errorf("%v information is missing in DUT", name)
                        continue
                }
                t.Logf("Validating SMART information for storage device: %v", name)

                smartDataInfo := device.GetSmartDataInfo()
                {
                        got := testhelper.StorageWriteAmplificationFactor(t, dut, &device)
                        thresholds := smartDataInfo.GetWriteAmplificationFactorThresholds()
                        if !thresholds.IsValid(got) {
                                t.Errorf("%v write-amplification-factor thresholds not met! got:%v, thresholds:[%v]",
                                        name, got, thresholds)
                        }
                }
                {
                        got := testhelper.StorageRawReadErrorRate(t, dut, &device)
                        thresholds := smartDataInfo.GetRawReadErrorRateThresholds()
                        if !thresholds.IsValid(got) {
                                t.Errorf("%v raw-read-error-rate thresholds not met! got:%v, thresholds:[%v]",
                                        name, got, thresholds)
                        }
                }
                {
                        got := testhelper.StorageThroughputPerformance(t, dut, &device)
                        thresholds := smartDataInfo.GetThroughputPerformanceThresholds()
                        if !thresholds.IsValid(got) {
                                t.Errorf("%v throughput-performance thresholds not met! got:%v, thresholds:[%v]",
                                        name, got, thresholds)
                        }
                }
                {
                        got := testhelper.StorageReallocatedSectorCount(t, dut, &device)
                        thresholds := smartDataInfo.GetReallocatedSectorCountThresholds()
                        if !thresholds.IsValid(got) {
                                t.Errorf("%v reallocated-sector-count thresholds not met! got:%v, thresholds:[%v]",
                                        name, got, thresholds)
                        }
                }
                {
                        got := testhelper.StoragePowerOnSeconds(t, dut, &device)
                        thresholds := smartDataInfo.GetPowerOnSecondsThresholds()
                        if !thresholds.IsValid(got) {
                                t.Errorf("%v power-on-seconds thresholds not met! got:%v, thresholds:[%v]",
                                        name, got, thresholds)
                        }
                }
                {
                        got := testhelper.StorageSsdLifeLeft(t, dut, &device)
                        thresholds := smartDataInfo.GetSsdLifeLeftThresholds()
                        if !thresholds.IsValid(got) {
                                t.Errorf("%v ssd-life-left thresholds not met! got:%v, thresholds:[%v]",
                                        name, got, thresholds)
                        }
                }
                {
                        got := testhelper.StorageAvgEraseCount(t, dut, &device)
                        thresholds := smartDataInfo.GetAvgEraseCountThresholds()
                        if !thresholds.IsValid(got) {
                                t.Errorf("%v avg-erase-count thresholds not met! got:%v, thresholds:[%v]",
                                        name, got, thresholds)
                        }
                }
                {
                        got := testhelper.StorageMaxEraseCount(t, dut, &device)
                        thresholds := smartDataInfo.GetMaxEraseCountThresholds()
                        if !thresholds.IsValid(got) {
                                t.Errorf("%v max-erase-count thresholds not met! got:%v, thresholds:[%v]",
                                        name, got, thresholds)
                        }
                }
        }
}


// Fan tests.
func TestFanInformation(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("a394f0d4-61a9-45a8-a05a-c738fa4fa4b2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	fans, err := testhelper.FanInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch fan information: %v", err)
	}

	for _, fan := range fans {
		name := fan.GetName()
		// Even though fan components might be removable, we expect all fans to be
		// present in the switch (unlike storage devices). Hence, we are fetching
		// fan component information instead of fetching the entire component subtree.
		info := gnmi.Get(t, dut, gnmi.OC().Component(name).State())

		if info.Type == nil {
			t.Errorf("%v missing type leaf", name)
		} else {
			if got, want := info.GetType(), oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_FAN; got != want {
				t.Errorf("%v type match failed! got:%v, want:%v", name, got, want)
			}
		}
		if info.Location == nil {
			t.Errorf("%v missing location leaf", name)
		} else {
			if got, want := info.GetLocation(), fan.GetLocation(); got != want {
				t.Errorf("%v location match failed! got:%v, want:%v", name, got, want)
			}
		}
		if info.Parent == nil {
			t.Errorf("%v missing parent leaf", name)
		} else {
			if got, want := info.GetParent(), fan.GetParent(); got != want {
				t.Errorf("%v parent match failed! got:%v, want:%v", name, got, want)
			}
		}
		if info.Removable == nil {
			t.Errorf("%v missing removable leaf", name)
		}
		if got, want := info.GetRemovable(), fan.GetIsRemovable(); got != want {
			t.Errorf("%v removable match failed! got:%v, want:%v", name, got, want)
		}
		if info.Empty == nil {
			t.Errorf("%v missing Empty leaf", name)
		} else {
			if info.GetEmpty() {
				t.Errorf("%v is unexpectedly empty.", name)
			}
		}

		// Only removable fans have FRU information.
		if fan.GetIsRemovable() == false {
			t.Logf("Not checking FRU information for %v since it is not removable", name)
			continue
		}

		if info.PartNo == nil {
			t.Errorf("%v missing part-no leaf", name)
		} else if info.GetPartNo() == "" {
			t.Errorf("%v has empty part-no", name)
		}
		if info.SerialNo == nil {
			t.Errorf("%v missing serial-no leaf", name)
		} else if info.GetSerialNo() == "" {
			t.Errorf("%v has empty serial-no", name)
		}

		// Fetch mfg-date leaf separately since we want the test to fail in case
		// of non-compliance errors with respect to the date format. Ondatra ignores
		// non-compliance errors at sub-tree level Get() but fails the test if there
		// is non-compliance at leaf level Get().
		if got := gnmi.Get(t, dut, gnmi.OC().Component(name).MfgDate().State()); got == "" {
			t.Errorf("%v has empty mfg-date", name)
		}
	}

	fantrays, err := testhelper.FanTrayInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch fan information: %v", err)
	}

	for _, fantray := range fantrays {
		name := fantray.GetName()
		// Likewise for fan trays, we expect all to be present regardless of whether they are removable.
		info := gnmi.Get(t, dut, gnmi.OC().Component(name).State())
		if info.Type == nil {
			t.Errorf("%v missing type leaf", name)
		}
		// } else {
		// 	if got, want := info.GetType(), oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_FANTRAY; got != want {
		// 		t.Errorf("%v type match failed! got:%v, want:%v", name, got, want)
		// 	}
		// }
		if info.Location == nil {
			t.Errorf("%v missing location leaf", name)
		} else {
			if got, want := info.GetLocation(), fantray.GetLocation(); got != want {
				t.Errorf("%v location match failed! got:%v, want:%v", name, got, want)
			}
		}
		if info.Parent == nil {
			t.Errorf("%v missing parent leaf", name)
		} else {
			if got, want := info.GetParent(), fantray.GetParent(); got != want {
				t.Errorf("%v parent match failed! got:%v, want:%v", name, got, want)
			}
		}
		if info.Removable == nil {
			t.Errorf("%v missing removable leaf", name)
		}
		if got, want := info.GetRemovable(), fantray.GetIsRemovable(); got != want {
			t.Errorf("%v removable match failed! got:%v, want:%v", name, got, want)
		}
		if info.Empty == nil {
			t.Errorf("%v missing Empty leaf", name)
		} else {
			if info.GetEmpty() {
				t.Errorf("%v is unexpectedly empty.", name)
			}
		}
	}
}

func TestFanSpeedInformation(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("804f6dbb-5480-4e1d-a215-e259530fa801").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	fans, err := testhelper.FanInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch fan information: %v", err)
	}

	for _, fan := range fans {
		name := fan.GetName()
		info := gnmi.Get(t, dut, gnmi.OC().Component(name).Fan().State())

		if info.Speed == nil {
			t.Errorf("%v missing speed leaf", name)
		} else {
			if got, want := info.GetSpeed(), fan.GetMaxSpeed(); got > want {
				t.Errorf("%v speed threshold exceeded! got:%v, want:<=%v", name, got, want)
			}
		}
		{
			if got := testhelper.FanSpeedControlPct(t, dut, &fan); got == 0 || got > 100 {
				t.Errorf("%v speed-control-pct failed! got:%v, want:range(0,100]", name, got)
			}
		}
	}
}

func validatePcieInformation(info any) error {
	if info == nil {
		return errors.New("PCIe information is nil")
	}

	var err error
	var totalErrors uint64
	var individualErrors uint64
	rv := reflect.ValueOf(info)
	rv = rv.Elem()
	for i := 0; i < rv.NumField(); i++ {
		name := rv.Type().Field(i).Name
		field := rv.Field(i)
		if field.IsNil() {
			err = testhelper.WrapError(err, "%v leaf is nil", name)
			continue
		}
		field = field.Elem()
		if got, want := field.Kind(), reflect.Uint64; got != want {
			err = testhelper.WrapError(err, "%v leaf has invalid value type! got:%v, want:%v", name, got, want)
			continue
		}

		value := field.Uint()
		if name == "TotalErrors" {
			totalErrors = value
		} else {
			individualErrors += value
		}
	}

	if totalErrors > individualErrors {
		err = testhelper.WrapError(err, "total-errors:%v should be <= cumulative-individual-errors:%v", totalErrors, individualErrors)
	} else if totalErrors == 0 && individualErrors > 0 {
		err = testhelper.WrapError(err, "total-errors count cannot be 0 if individual errors are detected (count:%v)", individualErrors)
	}

	return err
}

func TestPcieInformation(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("82e1ef7b-46db-4523-b0e5-f94a2e0a8a12").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	devices, err := testhelper.PcieInfoForDevice(t, dut)
	if err != nil {
		t.Fatalf("Failed to fetch PCIe information: %v", err)
	}

	for _, device := range devices {
		name := device.GetName()

		c := gnmi.Get(t, dut, gnmi.OC().Component(name).Pcie().CorrectableErrors().State())
		if err := validatePcieInformation(c); err != nil {
			t.Errorf("Correctable error information validation failed for device:%v\n%v", name, err)
		}

		f := gnmi.Get(t, dut, gnmi.OC().Component(name).Pcie().FatalErrors().State())
		if err := validatePcieInformation(f); err != nil {
			t.Errorf("Fatal error information validation failed for device:%v\n%v", name, err)
		}
		if f != nil && f.GetTotalErrors() != 0 {
			t.Errorf("%v fatal errors detected on %v", f.GetTotalErrors(), dut.Name())
		}

		n := gnmi.Get(t, dut, gnmi.OC().Component(name).Pcie().NonFatalErrors().State())
		if err := validatePcieInformation(n); err != nil {
			t.Errorf("Non-fatal error information validation failed for device:%v\n%v", name, err)
		}
	}
}

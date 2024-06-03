package platforms_hardware_component_test

import (
        "reflect"
        "regexp"
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

                fullyQualifiedName := "ju1u1m1b1s1i1.ibs40.net.google.com"
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

        fullyQualifiedName := "ju1u1m1b1s1i1.ibs40.net.google.com"
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

/ Health-indicator test.
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

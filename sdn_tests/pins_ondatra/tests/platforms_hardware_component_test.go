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

package gnmi_stress_test

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	gst "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/tests/ondatra/gnmi_stress_helper"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ygot/ygot"
	"google.golang.org/grpc"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

// gNMI load test short interval(30 minutes).
func TestGNMIShortStressTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("44fa854f-5d85-42aa-9ad0-4ee8dbce7f10").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressTestHelper(t, dut, gst.ShortStressTestInterval)
	gst.SanityCheck(t, dut)
}

// gNMI different leaf get test
func TestGNMISetUpdateDifferentLeafTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("08f9ffba-54a9-4d47-a3dc-0e4420fe296b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressSetTestHelper(t, dut, gst.AvgIteration, false)
}

// gNMI different leaf set update test
func TestGNMISetReplaceDifferentLeafTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("08f9ffba-54a9-4d47-a3dc-0e4420fe296b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressSetTestHelper(t, dut, gst.AvgIteration, true)
}

// gNMI different leaf set replace test
func TestGNMISetUpdateDifferentClientTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("389641b7-d995-4411-a222-e38caa9291a2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SetDifferentClientTest(t, dut, false)
}

// gNMI different leaf set update test
func TestGNMISetReplaceDifferentClientTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("389641b7-d995-4411-a222-e38caa9291a2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SetDifferentClientTest(t, dut, true)
}

// gNMI different leaf subscription poll mode test
func TestGNMISubscribePollDifferentLeafTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("08f9ffba-54a9-4d47-a3dc-0e4420fe296b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressTestSubsHelper(t, dut, false, true)
}

// gNMI different subtree subscription poll mode test
func TestGNMISubscribePollDifferentSubtreeTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("357762b4-4d34-467e-b321-90a2d271d50d").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressTestSubsHelper(t, dut, true, true)
}

// gNMI different Client Subscribe Poll test
func TestGNMISubscribePollDifferentClientTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("389641b7-d995-4411-a222-e38caa9291a2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SubscribeDifferentClientTest(t, dut, true)
}

// gNMI different leaf subscription Sample mode test
func TestGNMISubscribeSampleDifferentLeafTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("08f9ffba-54a9-4d47-a3dc-0e4420fe296b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressTestSubsHelper(t, dut, false, false)
}

// gNMI different subtree subscription Sample mode test
func TestGNMISubscribeSampleDifferentSubtreeTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("357762b4-4d34-467e-b321-90a2d271d50d").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressTestSubsHelper(t, dut, true, false)
}

// gNMI different Client Subscribe Sample test
func TestGNMISubscribeSampleDifferentClientTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("389641b7-d995-4411-a222-e38caa9291a2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SubscribeDifferentClientTest(t, dut, false)
}

// gNMI different Client random operations test
func TestGNMIRandomOpsDifferentClientTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("389641b7-d995-4411-a222-e38caa9291a2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.RandomDifferentClientTestHelper(t, dut, gst.ShortStressTestInterval)
}

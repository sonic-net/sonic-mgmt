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
	gst "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/tests/gnmi_stress_helper"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ygot/ygot"
	"google.golang.org/grpc"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

// gNMI load test - Replacing a single leaf 100 times.
func TestGNMILoadTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("f5e40be6-9913-4926-8d69-505e51f566f1").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	port, err := testhelper.RandomInterface(t, dut, nil)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}
	oldMtu := gnmi.Get(t, dut, gnmi.OC().Interface(port).Mtu().Config())
	gst.SanityCheck(t, dut, port)

	for i := gst.MinMtuStepInc; i < gst.MaxMtuStepInc; i++ {
		// Configure port MTU and verify that state path reflects configured MTU.
		mtu := uint16(1500 + i)
		gnmi.Replace(t, dut, gnmi.OC().Interface(port).Mtu().Config(), mtu)
		gst.CollectPerformanceMetrics(t, dut)
		got := gnmi.Get(t, dut, gnmi.OC().Interface(port).Mtu().Config())
		if got != mtu {
			t.Errorf("MTU matched failed! got:%v, want:%v", got, mtu)
		}
	}
	t.Logf("After 10 seconds of idle time, the performance metrics are:")
	time.Sleep(gst.IdleTime * time.Second)
	gst.CollectPerformanceMetrics(t, dut)
	// Replace the old MTU value as a test cleanup.
	gnmi.Replace(t, dut, gnmi.OC().Interface(port).Mtu().Config(), oldMtu)
	gst.SanityCheck(t, dut, port)

}

// gNMI load test short interval(30 minutes).
func TestGNMIShortStressTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("44fa854f-5d85-42aa-9ad0-4ee8dbce7f10").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.StressTestHelper(t, dut, gst.ShortStressTestInterval)
	gst.SanityCheck(t, dut)
}

// gNMI broken client test
func TestGNMIBrokenClientTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("cd36ba68-a2c1-485a-bc1a-c79463ed80d9").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	gst.SanityCheck(t, dut)
	for i := 0; i < gst.MinIteration; i++ {
		// Create getRequest message with ASCII encoding.
		getRequest := &gpb.GetRequest{
			Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Path: []*gpb.Path{{
				Elem: []*gpb.PathElem{{
					Name: "interfaces",
				}},
			}},
			Type:     gpb.GetRequest_ALL,
			Encoding: gpb.Encoding_PROTO,
		}
		t.Logf("GetRequest:\n%v", getRequest)

		// Fetch get client using the raw gNMI client.
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(context.Background(), grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		getResp, err := gnmiClient.Get(ctx, getRequest)
		if err == nil {
			t.Logf("GetResponse:\n%v", getResp)
			t.Fatalf("The getRequest is successfully received on broken client")
		}
		if getResp != nil {
			t.Fatalf("getResponse is received successfully")
		}
	}
	gst.SanityCheck(t, dut)
}

// gNMI different leaf get test
func TestGNMIGetDifferentLeafTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("08f9ffba-54a9-4d47-a3dc-0e4420fe296b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SanityCheck(t, dut)
	rand.Seed(time.Now().Unix())
	gst.CollectPerformanceMetrics(t, dut)
	for i := 0; i < gst.AvgIteration; i++ {
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		reqPath := fmt.Sprintf(gst.Path[rand.Intn(len(gst.Path))], port)
		// Create Get Request.
		sPath, err := ygot.StringToStructuredPath(reqPath)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}
		paths := []*gpb.Path{sPath}

		// Create getRequest message with data type.
		getRequest := &gpb.GetRequest{
			Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Path:     paths,
			Type:     gpb.GetRequest_ALL,
			Encoding: gpb.Encoding_PROTO,
		}
		t.Logf("GetRequest:\n%v", getRequest)

		// Fetch get client using the raw gNMI client.
		ctx := context.Background()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		getResp, err := gnmiClient.Get(ctx, getRequest)
		if err != nil {
			t.Fatalf("Error while calling Get Raw API: (%v)", err)
		}

		if getResp == nil {
			t.Fatalf("Get response is nil")
		}
		t.Logf("GetResponse:\n%v", getResp)
		gst.CollectPerformanceMetrics(t, dut)
	}
	t.Logf("After 10 seconds of idle time, the performance metrics are:")
	time.Sleep(gst.IdleTime * time.Second)
	gst.CollectPerformanceMetrics(t, dut)
	gst.SanityCheck(t, dut)
}

// gNMI different subtrees get test
func TestGNMIGetDifferentSubtreeTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("357762b4-4d34-467e-b321-90a2d271d50d").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SanityCheck(t, dut)
	rand.Seed(time.Now().Unix())
	gst.CollectPerformanceMetrics(t, dut)
	for i := 0; i < gst.MinIteration; i++ {
		reqPath := gst.Subtree[rand.Intn(len(gst.Subtree))]
		// Create Get Request.
		sPath, err := ygot.StringToStructuredPath(reqPath)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}
		// Create getRequest message with data type.
		getRequest := &gpb.GetRequest{
			Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Path:     []*gpb.Path{sPath},
			Type:     gpb.GetRequest_ALL,
			Encoding: gpb.Encoding_PROTO,
		}
		t.Logf("GetRequest:\n%v", getRequest)

		// Fetch get client using the raw gNMI client.
		ctx := context.Background()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		getResp, err := gnmiClient.Get(ctx, getRequest)
		if err != nil {
			t.Fatalf("Error while calling Get Raw API: (%v)", err)
		}

		if getResp == nil {
			t.Fatalf("Get response is nil")
		}
		t.Logf("GetResponse:\n%v", getResp)
		gst.CollectPerformanceMetrics(t, dut)
	}
	t.Logf("After 10 seconds of idle time, the performance metrics are:")
	time.Sleep(gst.IdleTime * time.Second)
	gst.CollectPerformanceMetrics(t, dut)
	gst.SanityCheck(t, dut)
}

// gNMI different Client get test
func TestGNMIGetDifferentClientTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("389641b7-d995-4411-a222-e38caa9291a2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SanityCheck(t, dut)
	ctx := context.Background()
	newGNMIClient := func() gpb.GNMIClient {
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		return gnmiClient
	}
	clients := map[string]gpb.GNMIClient{
		"c1":  newGNMIClient(),
		"c2":  newGNMIClient(),
		"c3":  newGNMIClient(),
		"c4":  newGNMIClient(),
		"c5":  newGNMIClient(),
		"c6":  newGNMIClient(),
		"c7":  newGNMIClient(),
		"c8":  newGNMIClient(),
		"c9":  newGNMIClient(),
		"c10": newGNMIClient(),
	}

	var wg sync.WaitGroup
	for k := range clients {
		v := k
		wg.Add(1)

		rand.Seed(time.Now().Unix())
		gst.CollectPerformanceMetrics(t, dut)
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		reqPath := fmt.Sprintf(gst.Path[rand.Intn(len(gst.Path))], port)
		// Create Get Request.
		sPath, err := ygot.StringToStructuredPath(reqPath)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}

		// Create getRequest message with data type.
		getRequest := &gpb.GetRequest{
			Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Path:     []*gpb.Path{sPath},
			Type:     gpb.GetRequest_ALL,
			Encoding: gpb.Encoding_PROTO,
		}
		t.Logf("GetRequest:\n%v", getRequest)

		// Fetch get client using the raw gNMI client.
		go func() {
			getResp, err := clients[v].Get(ctx, getRequest)
			if err != nil {
				t.Log("Error while calling Get Raw API")
			}
			if getResp == nil {
				t.Log("Get response is nil")
			}
			t.Logf("GetResponse:\n%v", getResp)
			wg.Done()
		}()

		gst.CollectPerformanceMetrics(t, dut)
	}
	wg.Wait()
	t.Logf("After 10 seconds of idle time, the performance metrics are:")
	time.Sleep(gst.IdleTime * time.Second)
	gst.CollectPerformanceMetrics(t, dut)
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

// gNMI different leaf set delete test
func TestGNMISetDeleteDifferentLeafTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("08f9ffba-54a9-4d47-a3dc-0e4420fe296b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SanityCheck(t, dut)
	rand.Seed(time.Now().Unix())
	gst.CollectPerformanceMetrics(t, dut)
	for i := 0; i < gst.AvgIteration; i++ {
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		gst.SetDefaultValuesHelper(t, dut, port)
		sPath, err := ygot.StringToStructuredPath(gst.RandomDeletePath(port))
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}

		paths := []*gpb.Path{sPath}

		// Create getRequest message with data type.
		getRequest := &gpb.GetRequest{
			Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Path:     paths,
			Type:     gpb.GetRequest_ALL,
			Encoding: gpb.Encoding_JSON_IETF,
		}
		t.Logf("GetRequest:\n%v", getRequest)

		// Fetch get client using the raw gNMI client.
		ctx := context.Background()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		getResp, err := gnmiClient.Get(ctx, getRequest)
		if err != nil {
			t.Fatalf("Error while calling Get Raw API: (%v)", err)
		}
		t.Logf("GetResponse:\n%v", getResp)

		setRequest := &gpb.SetRequest{
			Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Delete: []*gpb.Path{sPath},
		}
		t.Logf("SetRequest:\n%v", setRequest)

		// Fetch get client using the raw gNMI client.
		setResp, err := gnmiClient.Set(ctx, setRequest)
		if err != nil {
			t.Fatalf("Error while calling Get Raw API: (%v)", err)
		}

		if setResp == nil {
			t.Fatalf("set response is nil")
		}
		t.Logf("setResponse:\n%v", setResp)
		gst.CollectPerformanceMetrics(t, dut)

		// Restore the old values for the path

		if getResp != nil {
			updates, err := gst.UpdatesWithJSONIETF(getResp)
			if err != nil {
				t.Fatalf("Unable to get updates with JSON IETF: (%v)", err)
			}
			setRequest := &gpb.SetRequest{
				Prefix:  &gpb.Path{Origin: "openconfig", Target: dut.Name()},
				Replace: updates,
			}
			setResp, err := gnmiClient.Set(ctx, setRequest)
			if err != nil {
				t.Fatalf("Unable to restore the original value using set client (%v)", err)
			}
			t.Logf("SetResponse:\n%v", setResp)
		}
	}
	t.Logf("After %v seconds of idle time, collecting performance metrics", gst.IdleTime)
	time.Sleep(gst.IdleTime * time.Second)
	gst.CollectPerformanceMetrics(t, dut)
	gst.SanityCheck(t, dut)
}

// gNMI different subtrees set delete test
func TestGNMISetDeleteDifferentSubtreeTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("357762b4-4d34-467e-b321-90a2d271d50d").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SanityCheck(t, dut)
	rand.Seed(time.Now().Unix())
	gst.CollectPerformanceMetrics(t, dut)
	// Restore the config on the DUT after the test.
	defer func() {
		if err := testhelper.ConfigPush(t, dut, nil); err != nil {
			t.Fatalf("Failed to restore config: %v", err)
		}
	}()
	for i := 0; i < gst.MinIteration; i++ {
		reqPath := gst.DelSubtree[rand.Intn(len(gst.DelSubtree))]

		// Create Set Delete Request.
		sPath, err := ygot.StringToStructuredPath(reqPath)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}

		// Create getRequest message with data type.
		getRequest := &gpb.GetRequest{
			Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Path:     []*gpb.Path{sPath},
			Type:     gpb.GetRequest_CONFIG,
			Encoding: gpb.Encoding_JSON_IETF,
		}
		t.Logf("GetRequest:\n%v", getRequest)

		ctx := context.Background()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		getResp, err := gnmiClient.Get(ctx, getRequest)
		if err != nil {
			t.Fatalf("Error while calling Get Raw API: (%v)", err)
		}
		t.Logf("GetResponse:\n%v", getResp)

		setRequest := &gpb.SetRequest{
			Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Delete: []*gpb.Path{sPath},
		}
		t.Logf("SetRequest:\n%v", setRequest)

		// Fetch set delete client using the raw gNMI client.
		setResp, err := gnmiClient.Set(ctx, setRequest)
		if err != nil {
			t.Fatalf("Error while calling Get Raw API: (%v)", err)
		}
		if setResp == nil {
			t.Fatalf("set response is nil")
		}
		t.Logf("setResponse:\n%v", setResp)

		// Restore the old values.
		// A defer statement was not used to restore the values because this is in a for loop. The for
		// loop deletes a subtree and then restores the values after. The subtree that is chosen could
		// be chosen multiple times in the same test, so a defer would not work in this case.
		updates, err := gst.UpdatesWithJSONIETF(getResp)
		if err != nil {
			t.Fatalf("Unable to get updates with JSON IETF: (%v)", err)
		}
		setRequest = &gpb.SetRequest{
			Prefix:  &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Replace: updates,
		}
		setResp, err = gnmiClient.Set(ctx, setRequest)
		if err != nil {
			t.Fatalf("Unable to restore the original value using set client (%v)", err)
		}
		t.Logf("SetResponse:\n%v", setResp)
		gst.CollectPerformanceMetrics(t, dut)
	}
	t.Logf("After %v seconds of idle time, the performance metrics are collected", gst.IdleTime)
	time.Sleep(gst.IdleTime * time.Second)
	gst.CollectPerformanceMetrics(t, dut)
	gst.SanityCheck(t, dut)
}

// gNMI different Client set delete test
func TestGNMISetDeleteDifferentClientTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("389641b7-d995-4411-a222-e38caa9291a2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	gst.SanityCheck(t, dut)
	ctx := context.Background()
	newGNMIClient := func() gpb.GNMIClient {
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		return gnmiClient
	}
	clients := map[string]gpb.GNMIClient{
		"c1":  newGNMIClient(),
		"c2":  newGNMIClient(),
		"c3":  newGNMIClient(),
		"c4":  newGNMIClient(),
		"c5":  newGNMIClient(),
		"c6":  newGNMIClient(),
		"c7":  newGNMIClient(),
		"c8":  newGNMIClient(),
		"c9":  newGNMIClient(),
		"c10": newGNMIClient(),
	}
	info, err := testhelper.FetchPortsOperStatus(t, dut)
	if err != nil || info == nil {
		t.Fatalf("Failed to fetch ports oper-status: %v", err)
	}
	interfaces := info.Up
	numIntfs := len(interfaces)
	var port string

	var wg sync.WaitGroup
	for k := range clients {
		if len(interfaces) == 0 {
			t.Logf("Less operationally up interfaces than clients: %v interfaces, %v clients", numIntfs, len(clients))
			break
		}
		v := k
		wg.Add(1)

		rand.Seed(time.Now().Unix())
		gst.CollectPerformanceMetrics(t, dut)
		port, interfaces = interfaces[0], interfaces[1:]
		gst.SetDefaultValuesHelper(t, dut, port)
		sPath, err := ygot.StringToStructuredPath(gst.RandomDeletePath(port))
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}

		paths := []*gpb.Path{sPath}

		// Create getRequest message with data type.
		getRequest := &gpb.GetRequest{
			Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Path:     paths,
			Type:     gpb.GetRequest_ALL,
			Encoding: gpb.Encoding_PROTO,
		}
		t.Logf("GetRequest:\n%v", getRequest)

		setRequest := &gpb.SetRequest{
			Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Delete: []*gpb.Path{sPath},
		}
		t.Logf("SetRequest:\n%v", setRequest)
		ctx := context.Background()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		getResp, err := gnmiClient.Get(ctx, getRequest)
		if err != nil {
			t.Fatalf("Error while calling Get Raw API: (%v)", err)
		}
		t.Logf("GetResponse:\n%v", getResp)

		// Fetch get client using the raw gNMI client.
		go func() {
			// Fetch get client using the raw gNMI client.
			setResp, err := clients[v].Set(context.Background(), setRequest)
			if err != nil {
				t.Log("Error while calling Set delete Raw API")
			}
			if setResp == nil {
				t.Log("Set response is nil")
			}
			t.Logf("setResponse:\n%v", setResp)
			wg.Done()
		}()
		gst.CollectPerformanceMetrics(t, dut)
		// Restore the old values for the path
		gst.SetDefaultValuesHelper(t, dut, port)
	}
	wg.Wait()
	t.Logf("After %v seconds of idle time, colecting  performance metrics", gst.IdleTime)
	time.Sleep(gst.IdleTime * time.Second)
	gst.CollectPerformanceMetrics(t, dut)
	gst.SanityCheck(t, dut)
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

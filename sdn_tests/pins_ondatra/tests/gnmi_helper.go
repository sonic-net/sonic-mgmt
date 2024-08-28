package gnmi_stress_helper

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ygot/ygot"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/prototext"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmi/value"
)

// PathInfo structure defines the path info.
type PathInfo struct {
	path              string
	payload           string
	expectedResult    bool
	expectedResponse  any
	isUsingRandomIntf bool
}

// Paths are used in get and set tests randomly.
var Paths = []PathInfo{
	PathInfo{
		path:              "/interfaces/interface[name=%s]/config/mtu",
		payload:           strconv.FormatUint(uint64(9216), 10),
		expectedResult:    true,
		expectedResponse:  uint64(9216),
		isUsingRandomIntf: true,
	},
	PathInfo{
		path:              "/interfaces/interface[name=%s]/config/description",
		payload:           "\"test\"",
		expectedResult:    true,
		expectedResponse:  "\"test\"",
		isUsingRandomIntf: true,
	},
	PathInfo{
		path:              "/interfaces/interface[name=%s]/config/enabled",
		payload:           strconv.FormatBool(true),
		expectedResult:    true,
		expectedResponse:  true,
		isUsingRandomIntf: true,
	},
	PathInfo{
		path:              "/interfaces/interface[name=%s]/config/xyz",
		payload:           strconv.FormatBool(true),
		expectedResult:    false,
		expectedResponse:  `{}`,
		isUsingRandomIntf: true,
	},
	PathInfo{
		path:              "/interfaces/interface[name=%s]/config/description",
		payload:           "\"This is a description from gnmi helper.\"",
		expectedResult:    true,
		expectedResponse:  "\"This is a description from gnmi helper.\"",
		isUsingRandomIntf: true,
	},
	PathInfo{
		path:              "/interfaces/interface[name=%s]/config/health-indicator",
		payload:           "\"GOOD\"",
		expectedResult:    true,
		expectedResponse:  "\"GOOD\"",
		isUsingRandomIntf: true,
	},
	PathInfo{
		path:              "/interfaces/interface[name=%s]/config/fully-qualified-interface-name",
		payload:           "\"test_interface\"",
		expectedResult:    false,
		expectedResponse:  "\"test_interface\"",
		isUsingRandomIntf: true,
	},
	PathInfo{
		path:              "/openconfig-platform:components/abc",
		payload:           "{name: chassis}",
		expectedResult:    false,
		expectedResponse:  `{}`,
		isUsingRandomIntf: false,
	},
}

// Path list is a set of random interface paths.
var Path = []string{
	"/interfaces/interface[name=%s]/config/mtu",
	"/interfaces/interface[name=%s]/config/enabled",
	"/interfaces/interface[name=%s]/state/type",
	"/interfaces/interface[name=%s]/state/cpu",
}

// DeletePaths is a set of random interface paths for delete operations.
var DeletePaths = []PathInfo{
	PathInfo{
		path:    "/interfaces/interface[name=%s]/config/description",
		payload: "\"test_interface\"",
	},
}

// DelSubtree list is the possible combination of gNMI path subtrees.
var DelSubtree = []string{
	"qos/forwarding-groups/",
	"qos/queues/",
}

// Subtree list is the possible combination of gNMI path subtrees.
var Subtree = []string{
	"interfaces/",
	"qos/",
	"system/",
}

// list of gNMI operations
var ops = []string{
	"get",
	"set",
	"subscribe",
}

// The following payload used as config push payload during set stress tests.
const (
	ShortStressTestInterval = 600000000000   // 10 minute interval in ns
	LongStressTestInterval  = 28800000000000 // 8 hour interval in ns
	IdleTime                = 10             // 10 seconds for the DUT to cool down
	MinIteration            = 6
	AvgIteration            = 20
	MinMtuStepInc           = 100
	MaxMtuStepInc           = 200
	SampleInterval          = 2000000000
	Timeout                 = 3 * time.Second
	UpdatesOnly             = true
)

// ConfigPush function to push config via gNMI raw Set.
func ConfigPush(t *testing.T, dut *ondatra.DUTDevice) {
	// Create setRequest message.
	setRequest := &gpb.SetRequest{
		Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
		Replace: []*gpb.Update{{
			Path: &gpb.Path{Elem: []*gpb.PathElem{{Name: "/"}}},
			Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte("")}},
		}},
	}

	// Fetch set client using the raw gNMI client.
	ctx := context.Background()
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}
	setResp, err := gnmiClient.Set(ctx, setRequest)
	if err != nil {
		t.Fatalf("Error while calling Set API during config push: (%v)", err)
	}
	t.Logf("SetResponse:\n%v", setResp)
}

// SanityCheck function validates the sanity of the DUT
func SanityCheck(t *testing.T, dut *ondatra.DUTDevice, ports ...string) {
	t.Helper()
	if err := testhelper.GNOIAble(t, dut); err != nil {
		t.Fatalf("gNOI server is not running in the DUT")
	}
	if err := testhelper.GNMIAble(t, dut); err != nil {
		t.Fatalf("gNMI server is not running in the DUT")
	}
	if ports != nil {
		if err := testhelper.VerifyPortsOperStatus(t, dut, ports...); err != nil {
			t.Logf("Ports %v oper status is not up", ports)
			t.Fatalf("Ports are not oper upT")
		}
	}
}

// CollectPerformanceMetrics collect the system performance metrics via gNMI get
func CollectPerformanceMetrics(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	// TODO: Receiving DB connection error for both process and memory path,
	// backend is not implemented yet. The following code block can be
	// uncommented out once the implementation is complete
	/* memory := dut.Telemetry().System().Memory().Get(t)
	 t.Logf("System memory details:", memory.Physical, memory.Reserved)

	// Create getRequest message with ASCII encoding.
	getRequest := &gpb.GetRequest{
		Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
		Path: []*gpb.Path{{
			Elem: []*gpb.PathElem{{
				Name: "system",
			}, {
				Name: "processes",
			}},
		}},
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
		t.Fatalf("Unable to fetch get client (%v)", err)
	}
	if getResp == nil {
		t.Fatalf("Unable to fetch get client, get response is nil")
	}
	t.Logf("System Processes Info: %v", getResp)
	*/
}

// StressTestHelper function to invoke various gNMI set and get operations
func StressTestHelper(t *testing.T, dut *ondatra.DUTDevice, interval time.Duration) {
	SanityCheck(t, dut)
	rand.Seed(time.Now().Unix())
	CollectPerformanceMetrics(t, dut)
	t.Logf("Interval : %v", interval)

	// Simple gNMI get request followed by a gNMI set replace to stress the DUT.
	for timeout := time.Now().Add(interval); time.Now().Before(timeout); {
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		pathInfo := Paths[rand.Intn(len(Paths))]
		path := pathInfo.path
		if pathInfo.isUsingRandomIntf == true {
			path = fmt.Sprintf(pathInfo.path, port)
		}
		t.Logf("path : %v", path)
		// Create set the Request.
		sPath, err := ygot.StringToStructuredPath(path)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}
		pathList := []*gpb.Path{sPath}

		setRequest := &gpb.SetRequest{
			Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Update: []*gpb.Update{{
				Path: sPath,
				Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(pathInfo.payload)}},
			}},
		}
		t.Logf("SetRequest:\n%v", setRequest)
		// Fetch set client using the raw gNMI client.
		ctx := context.Background()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		setResp, err := gnmiClient.Set(ctx, setRequest)
		if pathInfo.expectedResult == true && err != nil {
			t.Fatalf("Unable to fetch set client (%v)", err)
		}
		t.Logf("SetResponse:\n%v", setResp)

		// Create getRequest message with data type.
		getRequest := &gpb.GetRequest{
			Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Path:     pathList,
			Type:     gpb.GetRequest_ALL,
			Encoding: gpb.Encoding_PROTO,
		}
		t.Logf("GetRequest:\n%v", getRequest)

		// Fetch get client using the raw gNMI client.
		getResp, err := gnmiClient.Get(ctx, getRequest)
		if pathInfo.expectedResult == true && err != nil {
			t.Fatalf("Error while calling Get Raw API: (%v)", err)
		}

		if pathInfo.expectedResult == true && getResp == nil {
			t.Fatalf("Get response is nil")
		}
		t.Logf("GetResponse:\n%v", getResp)
		CollectPerformanceMetrics(t, dut)
	}
	t.Logf("After 10 seconds of idle time, the performance metrics are:")
	time.Sleep(IdleTime * time.Second)
	CollectPerformanceMetrics(t, dut)
	SanityCheck(t, dut)

}

// StressSetTestHelper function to invoke various gNMI set and get operations
func StressSetTestHelper(t *testing.T, dut *ondatra.DUTDevice, interval int, replace bool) {
	SanityCheck(t, dut)
	rand.Seed(time.Now().Unix())
	CollectPerformanceMetrics(t, dut)
	t.Logf("Interval : %v", interval)

	// Simple gNMI get request followed by a gNMI set replace to stress the DUT.
	for i := 0; i < interval; i++ {
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		pathInfo := Paths[rand.Intn(len(Paths))]
		path := pathInfo.path
		if pathInfo.isUsingRandomIntf == true {
			path = fmt.Sprintf(pathInfo.path, port)
		}
		t.Logf("path : %v", path)
		// Create set the Request.
		sPath, err := ygot.StringToStructuredPath(path)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}
		paths := []*gpb.Path{sPath}
		getResp := &gpb.GetResponse{}

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
		if pathInfo.expectedResult == true {
			getResp, err = gnmiClient.Get(context.Background(), getRequest)
			if err == nil {
				t.Logf("The path is not populated")
			}
		}

		setRequest := &gpb.SetRequest{
			Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Update: []*gpb.Update{{
				Path: sPath,
				Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(pathInfo.payload)}},
			}},
		}
		if replace == true {
			setRequest = &gpb.SetRequest{
				Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
				Replace: []*gpb.Update{{
					Path: sPath,
					Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(pathInfo.payload)}},
				}},
			}
		}
		t.Logf("SetRequest:\n%v", setRequest)
		// Fetch set client using the raw gNMI client.
		setResp, err := gnmiClient.Set(context.Background(), setRequest)
		if pathInfo.expectedResult == true && err != nil {
			t.Fatalf("Unable to fetch set client (%v)", err)
		}
		t.Logf("SetResponse:\n%v", setResp)
		CollectPerformanceMetrics(t, dut)

		// Restore the old values for the path if the above set resulted in changing the values
		if getResp != nil && pathInfo.expectedResult == true {
			updates, err := UpdatesWithJSONIETF(getResp)
			if err != nil {
				t.Fatalf("Unable to get updates with JSON IETF: (%v)", err)
			}
			setRequest := &gpb.SetRequest{
				Prefix:  &gpb.Path{Origin: "openconfig", Target: dut.Name()},
				Replace: updates,
			}
			setResp, err := gnmiClient.Set(context.Background(), setRequest)
			if err != nil {
				t.Fatalf("Unable to restore the original value using set client (%v)", err)
			}
			t.Logf("SetResponse:\n%v", setResp)
		}

	}
	t.Logf("After 10 seconds of idle time, the performance metrics are:")
	time.Sleep(IdleTime * time.Second)
	CollectPerformanceMetrics(t, dut)
	SanityCheck(t, dut)

}

// ParseGetResponseHelper function will parse the gNMI get response to get the value
func ParseGetResponseHelper(t *testing.T, getResp *gpb.GetResponse) string {
	// Validate GET response.
	notifs := getResp.GetNotification()
	if len(notifs) != 1 {
		t.Fatalf("got %d notifications, want 1", len(notifs))
	}
	notif, updates := notifs[0], notifs[0].GetUpdate()
	if len(updates) < 1 {
		t.Fatalf("got %d updates in the notification, want 1", len(updates))
	}
	pathStr, err := ygot.PathToString(&gpb.Path{Elem: notif.GetPrefix().GetElem()})
	if err != nil {
		t.Fatalf("failed to convert elems (%v) to string: %v", notif.GetPrefix().GetElem(), err)
	}

	updatePath, err := ygot.PathToString(updates[0].GetPath())
	if err != nil {
		t.Fatalf("failed to convert path to string (%v): %v", updatePath, err)
	}
	gotPath := updatePath
	if pathStr != "/" {
		gotPath = pathStr + updatePath
	}
	t.Logf("The path is in the response:%v", gotPath)
	val := updates[0].GetVal()

	var gotVal any
	if val.GetJsonIetfVal() == nil {
		// Get Scalar value.
		gotVal, err = value.ToScalar(val)
		if err != nil {
			t.Logf("got %v, want scalar value", gotVal)
		}
		gotVal = fmt.Sprintf("%v", gotVal)
	} else {
		// Unmarshal json data to container.
		if err := json.Unmarshal(val.GetJsonIetfVal(), &gotVal); err != nil {
			t.Logf("could not unmarshal json data to container: %v", err)
		}
	}
	return gotVal.(string)
}

// SetDifferentClientTest function to invoke set operation from different clients
func SetDifferentClientTest(t *testing.T, dut *ondatra.DUTDevice, replace bool) {
	SanityCheck(t, dut)
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
		CollectPerformanceMetrics(t, dut)
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		// Create Set Request.
		pathInfo := Paths[rand.Intn(len(Paths))]
		path := pathInfo.path
		if pathInfo.isUsingRandomIntf == true {
			path = fmt.Sprintf(pathInfo.path, port)
		}
		t.Logf("path : %v", path)
		// Create set the Request.
		sPath, err := ygot.StringToStructuredPath(path)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}

		setRequest := &gpb.SetRequest{
			Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Update: []*gpb.Update{{
				Path: sPath,
				Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(pathInfo.payload)}},
			}},
		}
		if replace == true {
			setRequest = &gpb.SetRequest{
				Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
				Replace: []*gpb.Update{{
					Path: sPath,
					Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(pathInfo.payload)}},
				}},
			}
		}
		t.Logf("SetRequest:\n%v", setRequest)

		// Fetch get client using the raw gNMI client.
		go func() {
			setResp, err := clients[v].Set(context.Background(), setRequest)
			if err != nil {
				t.Log("Error while calling Get Raw API")
			}
			if setResp == nil {
				t.Log("Get response is nil")
			}
			t.Logf("GetResponse:\n%v", setResp)
			wg.Done()
		}()

		CollectPerformanceMetrics(t, dut)
	}
	wg.Wait()
	t.Logf("After 10 seconds of idle time, the performance metrics are:")
	time.Sleep(IdleTime * time.Second)
	CollectPerformanceMetrics(t, dut)
	SanityCheck(t, dut)
}

// SetDefaultValuesHelper function will set the default values for the paths if it doesn't exist already.
func SetDefaultValuesHelper(t *testing.T, dut *ondatra.DUTDevice, port string) {
	for i := 0; i < len(DeletePaths); i++ {
		pathInfo := DeletePaths[i]
		reqPath := fmt.Sprintf(pathInfo.path, port)
		// Create Set Request.
		sPath, err := ygot.StringToStructuredPath(reqPath)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}
		// Set the default value for the path if there is none
		setRequest := &gpb.SetRequest{
			Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
			Update: []*gpb.Update{{
				Path: sPath,
				Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(pathInfo.payload)}},
			}},
		}
		t.Logf("SetRequest:\n%v", setRequest)
		// Fetch set client using the raw gNMI client.
		ctx := context.Background()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		setResp, err := gnmiClient.Set(ctx, setRequest)
		if err != nil {
			t.Fatalf("Unable to fetch set client (%v)", err)
		}
		t.Logf("SetResponse:\n%v", setResp)
	}
}

// RandomDeletePath function will choose a ramdom path from list of paths
func RandomDeletePath(port string) string {
	pathInfo := DeletePaths[rand.Intn(len(DeletePaths))]
	reqPath := fmt.Sprintf(pathInfo.path, port)
	return reqPath
}

// VerifyFullResponse function will verify the subscription response message
func VerifyFullResponse(t *testing.T, subClient gpb.GNMI_SubscribeClient, timeout time.Duration) {
	t.Helper()
	// Process response from DUT.
	for {
		// Wait for response from DUT.
		res, err := subClient.Recv()
		if err != nil {
			t.Fatalf("Response error received from DUT (%v)", err)
		}

		switch v := res.Response.(type) {
		case *gpb.SubscribeResponse_Update:
			// Process Update message received in SubscribeResponse.
			updates := v.Update
			// Perform basic sanity on the Update message.
			for _, update := range updates.GetUpdate() {
				if update.Path == nil {
					t.Errorf("Invalid nil Path in update: %v", prototext.Format(update))
					continue
				}
				if update.Val == nil {
					t.Errorf("Invalid nil Val in update: %v", prototext.Format(update))
					continue
				}

				// Path is partially present in Prefix and partially in Update in the response.
				prefixStr, err := ygot.PathToString(updates.GetPrefix())
				if err != nil {
					t.Errorf("Failed to convert path to string (%v) %v", err, updates.GetPrefix())
					continue
				}
				elemStr, err := ygot.PathToString(update.Path)
				if err != nil {
					t.Errorf("Failed to convert path to string (%v) %v", err, update.Path)
					continue
				}
				pathStr := prefixStr + elemStr
				t.Logf("Path in the response:%v", pathStr)
			}
			return
		}
	}
}

// StressTestSubsHelper function to invoke various subscription operations
func StressTestSubsHelper(t *testing.T, dut *ondatra.DUTDevice, subtree bool, poll bool) {
	SanityCheck(t, dut)
	rand.Seed(time.Now().Unix())
	CollectPerformanceMetrics(t, dut)
	for i := 0; i < MinIteration; i++ {
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		reqPath := fmt.Sprintf(Path[rand.Intn(len(Path))], port)
		if subtree == true {
			reqPath = fmt.Sprintf(Subtree[rand.Intn(len(Subtree))])
		}
		// Create Subscribe Request.
		sPath, err := ygot.StringToStructuredPath(reqPath)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}
		req := &gpb.SubscribeRequest{
			Request: &gpb.SubscribeRequest_Subscribe{
				Subscribe: &gpb.SubscriptionList{
					Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
					Subscription: []*gpb.Subscription{
						&gpb.Subscription{
							Path:           &gpb.Path{Elem: sPath.Elem},
							Mode:           gpb.SubscriptionMode_SAMPLE,
							SampleInterval: SampleInterval,
						}},
					Mode:        gpb.SubscriptionList_STREAM,
					Encoding:    gpb.Encoding_PROTO,
					UpdatesOnly: UpdatesOnly,
				},
			},
		}
		if poll == true {
			req = &gpb.SubscribeRequest{
				Request: &gpb.SubscribeRequest_Subscribe{
					Subscribe: &gpb.SubscriptionList{
						Subscription: []*gpb.Subscription{
							&gpb.Subscription{
								Path: &gpb.Path{Elem: sPath.Elem},
							}},
						Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
						Mode:     gpb.SubscriptionList_POLL,
						Encoding: gpb.Encoding_PROTO,
					},
				},
			}
		}
		t.Logf("Subscribe request:%v", req)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		subscribeClient, err := gnmiClient.Subscribe(ctx)
		if err != nil {
			t.Fatalf("Unable to get subscribe client (%v)", err)
		}

		if err := subscribeClient.Send(req); err != nil {
			t.Fatalf("Failed to send gNMI subscribe request (%v)", err)
		}
		if _, err := subscribeClient.Recv(); err != nil {
			t.Fatalf("Failed to receive gNMI sample subscribe request (%v)", err)
		}
		CollectPerformanceMetrics(t, dut)
	}
	t.Logf("After %v seconds of idle time, the performance metrics are collected", IdleTime)
	time.Sleep(IdleTime * time.Second)
	CollectPerformanceMetrics(t, dut)
	SanityCheck(t, dut)
}

// SubscribeDifferentClientTest function to invoke set operation from different clients
func SubscribeDifferentClientTest(t *testing.T, dut *ondatra.DUTDevice, poll bool) {
	SanityCheck(t, dut)
	clients := map[string]gpb.GNMIClient{}
	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		clients[fmt.Sprintf("c%d", i)] = gnmiClient
	}

	var wg sync.WaitGroup
	for k := range clients {
		v := k
		wg.Add(1)
		SanityCheck(t, dut)
		rand.Seed(time.Now().Unix())
		CollectPerformanceMetrics(t, dut)
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		reqPath := fmt.Sprintf(Path[rand.Intn(len(Path))], port)
		// Create Subscribe Request.
		sPath, err := ygot.StringToStructuredPath(reqPath)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}
		req := &gpb.SubscribeRequest{
			Request: &gpb.SubscribeRequest_Subscribe{
				Subscribe: &gpb.SubscriptionList{
					Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
					Subscription: []*gpb.Subscription{
						&gpb.Subscription{
							Path:           &gpb.Path{Elem: sPath.Elem},
							Mode:           gpb.SubscriptionMode_SAMPLE,
							SampleInterval: SampleInterval,
						}},
					Mode:        gpb.SubscriptionList_STREAM,
					Encoding:    gpb.Encoding_PROTO,
					UpdatesOnly: UpdatesOnly,
				},
			},
		}
		if poll == true {
			req = &gpb.SubscribeRequest{
				Request: &gpb.SubscribeRequest_Subscribe{
					Subscribe: &gpb.SubscriptionList{
						Subscription: []*gpb.Subscription{
							&gpb.Subscription{
								Path: &gpb.Path{Elem: sPath.Elem},
							}},
						Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
						Mode:     gpb.SubscriptionList_POLL,
						Encoding: gpb.Encoding_PROTO,
					},
				},
			}
		}
		t.Logf("Subscribe request:%v", req)
		// Fetch get client using the raw gNMI client.
		go func() {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			client, err := clients[v].Subscribe(ctx)
			if err != nil {
				t.Logf("Unable to get subscribe client (%v)", err)
			}
			if err := client.Send(req); err != nil {
				t.Logf("Failed to send gNMI subscribe request (%v)", err)
			}
			_, error := client.Recv()
			if error != nil {
				t.Logf("Response error received from DUT (%v)", error)
			}
			CollectPerformanceMetrics(t, dut)
			wg.Done()
		}()
	}
	wg.Wait()
	t.Logf("After %v seconds of idle time, the performance metrics are collected", IdleTime)
	time.Sleep(IdleTime * time.Second)
	CollectPerformanceMetrics(t, dut)
	SanityCheck(t, dut)
}

func selectgNMIPathHelper(t *testing.T, ops string, port string) (string, string, bool) {
	t.Helper()
	var path string
	if ops == "set" {
		pathInfo := Paths[rand.Intn(len(Paths))]
		path = pathInfo.path
		if pathInfo.isUsingRandomIntf == true {
			path = fmt.Sprintf(pathInfo.path, port)
		}
		return path, pathInfo.payload, pathInfo.expectedResult
	}
	path = fmt.Sprintf(Path[rand.Intn(len(Path))], port)
	return path, "", false
}

// RandomDifferentClientTestHelper function to invoke various gNMI operation from different clients
func RandomDifferentClientTestHelper(t *testing.T, dut *ondatra.DUTDevice, interval time.Duration) {
	SanityCheck(t, dut)
	clients := map[string]gpb.GNMIClient{}
	ctx := context.Background()
	newGNMIClient := func() gpb.GNMIClient {
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		return gnmiClient
	}
	for i := 1; i <= MinIteration; i++ {
		clients[fmt.Sprintf("c%d", i)] = newGNMIClient()
	}

	var wg sync.WaitGroup
	t.Logf("Interval : %v", interval)
	for timeout := time.Now().Add(interval); time.Now().Before(timeout); {
		// Create a gNMI Request.
		rand.Seed(time.Now().Unix())
		ops := ops[rand.Intn(len(ops))]
		port, err := testhelper.RandomInterface(t, dut, nil)
		if err != nil {
			t.Fatalf("Failed to fetch random interface: %v", err)
		}
		path, payload, expectedResult := selectgNMIPathHelper(t, ops, port)
		t.Logf("The path expect the valid result: %v", expectedResult)
		sPath, err := ygot.StringToStructuredPath(path)
		if err != nil {
			t.Fatalf("Unable to convert string to path (%v)", err)
		}
		for k := range clients {
			v := k
			wg.Add(1)
			CollectPerformanceMetrics(t, dut)
			if ops == "get" {
				// Create getRequest message with data type.
				req := &gpb.GetRequest{
					Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
					Path:     []*gpb.Path{sPath},
					Type:     gpb.GetRequest_ALL,
					Encoding: gpb.Encoding_PROTO,
				}
				t.Logf("GetRequest:\n%v", req)
				// Fetch get client using the raw gNMI client.
				go func() {
					setResp, err := clients[v].Get(ctx, req)
					if err != nil {
						t.Log("Error while calling Get Raw API")
					}
					if setResp == nil {
						t.Log("Get response is nil")
					}
					t.Logf("GetResponse:\n%v", setResp)
					wg.Done()
				}()
			} else if ops == "set" {
				paths := []*gpb.Path{sPath}
				getResp := &gpb.GetResponse{}

				// Create getRequest message with data type.
				getRequest := &gpb.GetRequest{
					Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
					Path:     paths,
					Type:     gpb.GetRequest_ALL,
					Encoding: gpb.Encoding_JSON_IETF,
				}
				t.Logf("GetRequest:\n%v", getRequest)

				gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
				if err != nil {
					t.Fatalf("Unable to get gNMI client (%v)", err)
				}

				// Fetch get client using the raw gNMI client.
				if expectedResult == true {
					getResp, err = gnmiClient.Get(ctx, getRequest)
					if err == nil {
						t.Logf("The path is not populated")
					}
				}
				req := &gpb.SetRequest{
					Prefix: &gpb.Path{Origin: "openconfig", Target: dut.Name()},
					Update: []*gpb.Update{{
						Path: sPath,
						Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(payload)}},
					}},
				}
				t.Logf("SetRequest:\n%v", req)
				// Fetch set client using the raw gNMI client.
				go func() {
					setResp, err := clients[v].Set(ctx, req)
					if err != nil {
						t.Logf("Error while calling Set Raw API: %v\n", err)
					}
					if setResp == nil {
						t.Log("Set response is nil")
					}
					t.Logf("SetResponse:\n%v", setResp)
					wg.Done()
				}()
				// Restore the old values for the path if the above set resulted in changing the values
				if getResp != nil && expectedResult == true {
					updates, err := UpdatesWithJSONIETF(getResp)
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
			} else {
				req := &gpb.SubscribeRequest{
					Request: &gpb.SubscribeRequest_Subscribe{
						Subscribe: &gpb.SubscriptionList{
							Subscription: []*gpb.Subscription{
								&gpb.Subscription{
									Path: &gpb.Path{Elem: sPath.Elem},
								}},
							Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
							Mode:     gpb.SubscriptionList_ONCE,
							Encoding: gpb.Encoding_PROTO,
						},
					},
				}
				t.Logf("Subscribe request:%v", req)
				// Fetch get client using the raw gNMI client.
				go func() {
					ctx, cancel := context.WithCancel(ctx)
					defer cancel()
					client, err := clients[v].Subscribe(ctx)
					if err != nil {
						t.Logf("Unable to get subscribe client (%v)", err)
					}
					if err := client.Send(req); err != nil {
						t.Logf("Failed to send gNMI subscribe request (%v)", err)
					}
					_, error := client.Recv()
					if error != nil {
						t.Logf("Response error received from DUT (%v)", error)
					}
					wg.Done()
				}()
			}
			CollectPerformanceMetrics(t, dut)
		}
		wg.Wait()
	}
	t.Logf("After %v seconds of idle time, the performance metrics are collected", IdleTime)
	time.Sleep(IdleTime * time.Second)
	CollectPerformanceMetrics(t, dut)
	SanityCheck(t, dut)
}

// UpdatesWithJSONIETF parses a Get Response and returns the Updates in the correct format
// to be used in a Set Request. This is useful for restoring the contents of a Get Response. The
// Get Response must be encoded in JSON IETF, specified by the Get Request.
func UpdatesWithJSONIETF(getResp *gpb.GetResponse) ([]*gpb.Update, error) {
	updates := []*gpb.Update{}
	for _, notification := range getResp.GetNotification() {
		if notification == nil {
			return nil, fmt.Errorf("Notification in GetResponse is empty")
		}
		for _, update := range notification.GetUpdate() {
			if update == nil {
				return nil, fmt.Errorf("Update in Notification is empty")
			}
			jsonVal := update.GetVal().GetJsonIetfVal()
			jsonMap := make(map[string]json.RawMessage)
			err := json.Unmarshal(jsonVal, &jsonMap)
			if err != nil {
				return nil, err
			}
			if len(jsonMap) == 1 {
				for _, v := range jsonMap {
					jsonVal, err = v.MarshalJSON()
					if err != nil {
						return nil, err
					}
				}
			}
			updates = append(updates, &gpb.Update{
				Path: update.GetPath(),
				Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: jsonVal}},
			})
		}
	}
	return updates, nil
}

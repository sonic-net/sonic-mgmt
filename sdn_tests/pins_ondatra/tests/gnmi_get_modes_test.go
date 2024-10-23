package gnmi_get_modes_test

import (
	"fmt"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/openconfig/gnmi/value"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/encoding/prototext"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	compStatePath       = "/components/component[name=%s]/state"
	compFwVerPath       = "/components/component[name=%s]/state/firmware-version"
	compParentStatePath = "/components/component[name=%s]/state/parent"
	intfPath            = "/interfaces/interface[name=%s]"
	intfMtuPath         = "/interfaces/interface[name=%s]/%s/mtu"
	intfNamePath        = "/interfaces/interface[name=%s]/%s/name"
	intfConfigPath      = "/interfaces/interface[name=%s]/config"
	intfStatePath       = "/interfaces/interface[name=%s]/state"
	intfCtrsPath        = "/interfaces/interface[name=%s]/state/counters"
	intfCtrsStatePath   = "/interfaces/interface[name=%s]/state/counters/in-octets"
	intfMgmtStatePath   = "/interfaces/interface[name=%s]/state/management"
)

var ignorePaths = []string{
	"/gnmi-pathz-policy-counters/paths/path",
}

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

/*
	TODO: Refactor the code to remove getDataTypeTest, and have
different table-driven tests for different methods of getDataTypeTest.
*/
type getDataTypeTest struct {
	uuid       string
	reqPath    string
	dataType   gpb.GetRequest_DataType
	wantVal    any
	wantNotVal string
}

func TestGNMIGetModes(t *testing.T) {
        dut := ondatra.DUT(t, "DUT")
        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        // Check if the switch is responsive with Get API, which will panic if the switch does not return
        // state value for specified interface Openconfig path resulting in a test failure.
        mtuVal := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().State())

        testCases := []struct {
                name     string
                function func(*testing.T)
        }{
                {
                        name: "GetConfigTypeConfigLeaf",
                        function: getDataTypeTest{
                                uuid:     "89f2834b-9ce2-4347-ad08-aa2e5b44e994",
                                reqPath:  fmt.Sprintf(intfMtuPath, intf, "config"),
                                dataType: gpb.GetRequest_CONFIG,
                                wantVal:  uint64(mtuVal),
                        }.dataTypeForLeafNonEmpty,
                },
                {
                        name: "GetConfigTypeConfigSubtree",
                        function: getDataTypeTest{
                                uuid:     "7ee2bf60-8f55-4bdd-a56e-e9a7c37c0611",
                                reqPath:  fmt.Sprintf(intfConfigPath, intf),
                                dataType: gpb.GetRequest_CONFIG,
                                wantVal:  fmt.Sprintf(intfConfigPath, intf),
                        }.dataTypeForNonLeafNonEmpty,
                },
                {
                        name: "GetConfigTypeStateLeaf",
                        function: getDataTypeTest{
                                uuid:     "6cd51db0-b1e5-405b-81b9-6d76b28014c3",
                                reqPath:  fmt.Sprintf(intfMtuPath, intf, "state"),
                                dataType: gpb.GetRequest_CONFIG,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetConfigTypeStateSubtree",
                        function: getDataTypeTest{
                                uuid:     "5685f240-67ce-4eaf-a842-0ae5e5ff470b",
                                reqPath:  fmt.Sprintf(intfStatePath, intf),
                                dataType: gpb.GetRequest_CONFIG,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetConfigTypeOperationalLeaf",
                        function: getDataTypeTest{
                                uuid:     "ab3bb6f3-a85b-4f61-a1fd-01b338aab111",
                                reqPath:  fmt.Sprintf(intfCtrsStatePath, intf),
                                dataType: gpb.GetRequest_CONFIG,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetConfigTypeOperationalSubtree",
                        function: getDataTypeTest{
                                uuid:     "93eff08c-3177-4097-90d3-5bcf42756a96",
                                reqPath:  fmt.Sprintf(intfCtrsPath, intf),
                                dataType: gpb.GetRequest_CONFIG,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetConfigTypeRoot",
                        function: getDataTypeTest{
                                uuid:       "88844ea0-328e-4b96-9454-b426d956a7c7",
                                dataType:   gpb.GetRequest_CONFIG,
                                wantVal:    []string{"/config/"},
                                wantNotVal: "/state/",
                        }.dataTypeForRootNonEmpty,
                },
                {
                        name: "GetStateTypeConfigLeaf",
                        function: getDataTypeTest{
                                uuid:     "fda99c23-3f28-49e9-9242-f116f633519a",
                                reqPath:  fmt.Sprintf(intfMtuPath, intf, "config"),
                                dataType: gpb.GetRequest_STATE,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetStateTypeConfigSubtree",
                        function: getDataTypeTest{
                                uuid:     "089f5aca-a8ba-4862-9238-96424b67035f",
                                reqPath:  fmt.Sprintf(intfConfigPath, intf),
                                dataType: gpb.GetRequest_STATE,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetStateTypeStateLeaf",
                        function: getDataTypeTest{
                                uuid:     "e091452a-ea18-423d-9c57-f42d8737012b",
                                reqPath:  fmt.Sprintf(intfMtuPath, intf, "state"),
                                dataType: gpb.GetRequest_STATE,
                                wantVal:  uint64(mtuVal),
                        }.dataTypeForLeafNonEmpty,
                },
                {
                        name: "GetStateTypeStateSubtree",
                        function: getDataTypeTest{
                                uuid:     "310a421e-eb94-4371-b0a4-557136f51ed9",
                                reqPath:  fmt.Sprintf(intfStatePath, intf),
                                dataType: gpb.GetRequest_STATE,
                                wantVal:  fmt.Sprintf(intfStatePath, intf),
                        }.dataTypeForNonLeafNonEmpty,
                },
                {
                        name: "GetStateTypeOperationalLeaf",
                        function: getDataTypeTest{
                                uuid:     "3b0bd721-0778-4f01-b2ac-927c63f023e1",
                                reqPath:  fmt.Sprintf(compParentStatePath, "os0"),
                                dataType: gpb.GetRequest_STATE,
                                wantVal:  "chassis",
                        }.dataTypeForLeafNonEmpty,
                },
                {
                        name: "GetStateTypeOperationalSubtree",
                        function: getDataTypeTest{
                                uuid:     "3f937fa1-31ae-4338-b3d7-bc7408106040",
                                reqPath:  fmt.Sprintf(intfCtrsPath, intf),
                                dataType: gpb.GetRequest_STATE,
                                wantVal:  fmt.Sprintf(intfCtrsPath, intf),
                        }.dataTypeForNonLeafNonEmpty,
                },
                {
                        name: "GetStateTypeRoot",
                        function: getDataTypeTest{
                                uuid:       "6b876b6c-e589-4611-a9eb-157fd5898e5d",
                                dataType:   gpb.GetRequest_STATE,
                                wantVal:    []string{"/state/"},
                                wantNotVal: "/config/",
                        }.dataTypeForRootNonEmpty,
                },
                {
                        name: "GetOperationalTypeConfigLeaf",
                        function: getDataTypeTest{
                                uuid:     "76209f70-069f-4bb0-b2b3-43e17c1ca955",
                                reqPath:  fmt.Sprintf(intfNamePath, intf, "config"),
                                dataType: gpb.GetRequest_OPERATIONAL,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetOperationalTypeConfigSubtree",
                        function: getDataTypeTest{
                                uuid:     "a6bcac89-4cc4-42d9-b1b5-fe8c32389ae4",
                                reqPath:  fmt.Sprintf(intfConfigPath, intf),
                                dataType: gpb.GetRequest_OPERATIONAL,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetOperationalTypeStateLeaf",
                        function: getDataTypeTest{
                                uuid:     "45013a6f-bdda-420d-9c7a-fc23e4946fac",
                                reqPath:  fmt.Sprintf(intfNamePath, intf, "state"),
                                dataType: gpb.GetRequest_OPERATIONAL,
                                wantVal:  `{}`,
                        }.dataTypeForPathEmpty,
                },
                {
                        name: "GetOperationalTypeStateSubtree",
                        function: getDataTypeTest{
                                uuid:     "ccc00a4c-8c80-4379-bf41-eb5554a3fad0",
                                reqPath:  fmt.Sprintf(intfStatePath, intf),
                                dataType: gpb.GetRequest_OPERATIONAL,
                                wantVal:  fmt.Sprintf(intfStatePath, intf),
                        }.dataTypeForNonLeafNonEmpty,
                },
                {
                        name: "GetOperationalTypeOperationalLeaf",
                        function: getDataTypeTest{
                                uuid:     "c829fd56-7452-4cf1-8a51-8b6ad80ed109",
                                reqPath:  fmt.Sprintf(intfMgmtStatePath, intf),
                                dataType: gpb.GetRequest_OPERATIONAL,
                                wantVal:  false,
                        }.dataTypeForLeafNonEmpty,
                },
                {
                        name: "GetOperationalTypeRoot",
                        function: getDataTypeTest{
                                uuid:    "1c27789a-de88-4cb4-9b17-6ecc2018423e",
                                reqPath: "/",
                        }.operationalUpdateNotInConfigCheck,
                },
                {
                        name: "GetOperationalTypeSubTree",
                        function: getDataTypeTest{
                                uuid:    "f65f9291-b695-4f89-b9d8-26443bcd26d1",
                                reqPath: fmt.Sprintf(intfPath, intf),
                        }.operationalUpdateNotInConfigCheck,
                },
                {
                        name: "GetAllTypeConfigLeaf",
                        function: getDataTypeTest{
                                uuid:     "acbc0dce-9e4c-4005-ae9d-b00e7bfb63ff",
                                reqPath:  fmt.Sprintf(intfMtuPath, intf, "config"),
                                dataType: gpb.GetRequest_ALL,
                                wantVal:  uint64(mtuVal),
                        }.dataTypeForLeafNonEmpty,
                },
                {
                        name: "GetAllTypeConfigSubtree",
                        function: getDataTypeTest{
                                uuid:     "b565e2cb-de9c-4ea1-99b2-88a63ea93981",
                                reqPath:  fmt.Sprintf(intfConfigPath, intf),
                                dataType: gpb.GetRequest_ALL,
                                wantVal:  fmt.Sprintf(intfConfigPath, intf),
                        }.dataTypeForNonLeafNonEmpty,
                },
                {
                        name: "GetAllTypeStateLeaf",
                        function: getDataTypeTest{
                                uuid:     "f010154c-ef5b-4068-b4aa-c5dc54e02303",
                                reqPath:  fmt.Sprintf(intfMtuPath, intf, "state"),
                                dataType: gpb.GetRequest_ALL,
                                wantVal:  uint64(mtuVal),
                        }.dataTypeForLeafNonEmpty,
                },
                {
                        name: "GetAllTypeStateSubtree",
                        function: getDataTypeTest{
                                uuid:     "45e1f65e-02d3-4c7c-a1e0-f84ebcc6db93",
                                reqPath:  fmt.Sprintf(intfStatePath, intf),
                                dataType: gpb.GetRequest_ALL,
                                wantVal:  fmt.Sprintf(intfStatePath, intf),
                        }.dataTypeForNonLeafNonEmpty,
                },
                {
                        name: "GetAllTypeOperationalLeaf",
                        function: getDataTypeTest{
                                uuid:     "35961781-c3d6-4c50-9ea2-bb1b9c09a6f2",
                                reqPath:  fmt.Sprintf(compParentStatePath, "os0"),
                                dataType: gpb.GetRequest_ALL,
                                wantVal:  "chassis",
                        }.dataTypeForLeafNonEmpty,
                },
                {
                        name: "GetAllTypeOperationalSubtree",
                        function: getDataTypeTest{
                                uuid:     "f9e27f17-5bb6-4e04-b07a-181bdb6628b8",
                                reqPath:  fmt.Sprintf(intfStatePath, intf),
                                dataType: gpb.GetRequest_ALL,
                                wantVal:  fmt.Sprintf(intfStatePath, intf),
                        }.dataTypeForNonLeafNonEmpty,
                },
                {
                        name: "GetAllTypeRoot",
                        function: getDataTypeTest{
                                uuid:     "0993eb99-ea29-485d-88b1-694f030ffa1c",
                                dataType: gpb.GetRequest_STATE,
                                wantVal:  []string{"/state/", "/config/"},
                        }.dataTypeForRootNonEmpty,
                },
                {
                        name: "GetConsistencyConfigLeaf",
                        function: getDataTypeTest{
                                uuid:     "13068a17-affc-46dc-a9f4-ef8639d70c8f",
                                reqPath:  fmt.Sprintf(intfMtuPath, intf, "config"),
                                dataType: gpb.GetRequest_CONFIG,
                        }.consistencyCheckLeafLevel,
                },
                {
                        name: "GetConsistencyStateLeaf",
                        function: getDataTypeTest{
                                uuid:     "1db85b3d-ac1c-422e-a4ea-108a71393773",
                                reqPath:  fmt.Sprintf(intfMtuPath, intf, "state"),
                                dataType: gpb.GetRequest_STATE,
                        }.consistencyCheckLeafLevel,
                },
                {
                        name: "GetConsistencyOperationalLeaf",
                        function: getDataTypeTest{
                                uuid:     "319cb11c-70e2-4f59-a39c-8e804685728d",
                                reqPath:  fmt.Sprintf(compFwVerPath, "chassis"),
                                dataType: gpb.GetRequest_OPERATIONAL,
                        }.consistencyCheckLeafLevel,
                },
                {
                        name: "GetConsistencyConfigSubtree",
                        function: getDataTypeTest{
                                uuid:     "036b0a6f-91eb-41ce-9efa-92da9812cc29",
                                reqPath:  fmt.Sprintf(intfConfigPath, intf),
                                dataType: gpb.GetRequest_CONFIG,
                        }.consistencyCheckSubtreeLevel,
                },
                {
                        name: "GetConsistencyStateSubtree",
                        function: getDataTypeTest{
                                uuid:     "3b215c64-33c7-47b9-8ec5-01f378e09b68",
                                reqPath:  fmt.Sprintf(compStatePath, "os0"),
                                dataType: gpb.GetRequest_STATE,
                        }.consistencyCheckSubtreeLevel,
                },
        }

        for _, testCase := range testCases {
                t.Run(testCase.name, testCase.function) // Calls the sub-test method.
        }
}

// Helper function to create the Get Request.
func createGetRequest(dut *ondatra.DUTDevice, paths []*gpb.Path, dataType gpb.GetRequest_DataType) *gpb.GetRequest {
	// Add Prefix information for the GetRequest.
	prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
	// Create getRequest message with data type.
	getRequest := &gpb.GetRequest{
		Prefix:   prefix,
		Path:     paths,
		Type:     dataType,
		Encoding: gpb.Encoding_PROTO,
	}
	return getRequest
}

// Test for gNMI Get for Data Type for Leaf path when non-empty subtree is returned.
func (c getDataTypeTest) dataTypeForLeafNonEmpty(t *testing.T) {
	t.Helper()
	defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Create Get Request.
	sPath, err := ygot.StringToStructuredPath(c.reqPath)
	if err != nil {
		t.Fatalf("Unable to convert string to path (%v)", err)
	}
	paths := []*gpb.Path{sPath}
	getRequest := createGetRequest(dut, paths, c.dataType)
	t.Logf("GetRequest:\n%v", getRequest)

	// Send Get request using the raw gNMI client.
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

	// Validate GET response.
	notifs := getResp.GetNotification()
	if len(notifs) != 1 {
		t.Fatalf("got %d notifications, want 1", len(notifs))
	}
	notif, updates := notifs[0], notifs[0].GetUpdate()
	if len(updates) != 1 {
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
	if gotPath != c.reqPath {
		t.Fatalf("got %s path, want %s path", gotPath, c.reqPath)
	}
	val := updates[0].GetVal()

	var gotVal any
	if val.GetJsonIetfVal() == nil {
		// Get Scalar value.
		gotVal, err = value.ToScalar(val)
		if err != nil {
			t.Errorf("got %v, want scalar value", gotVal)
		}
	} else {
		// Unmarshal json data to container.
		if err := json.Unmarshal(val.GetJsonIetfVal(), &gotVal); err != nil {
			t.Fatalf("could not unmarshal json data to container: %v", err)
		}
		var wantJSONStruct any
		if err := json.Unmarshal([]byte(c.wantVal.(string)), &wantJSONStruct); err != nil {
			t.Fatalf("could not unmarshal json data to container: %v", err)
		}
		c.wantVal = wantJSONStruct
	}
	if !cmp.Equal(gotVal, c.wantVal) {
		t.Fatalf("got %v value with type %T, want %v value with type %T", gotVal, gotVal, c.wantVal, c.wantVal)
	}
}

// Test for gNMI Get for Data Type for path when empty subtree is returned.
func (c getDataTypeTest) dataTypeForPathEmpty(t *testing.T) {
        t.Helper()
        defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Create Get Request.
        sPath, err := ygot.StringToStructuredPath(c.reqPath)
        if err != nil {
                t.Fatalf("Unable to convert string to path (%v)", err)
        }
        paths := []*gpb.Path{sPath}
        getRequest := createGetRequest(dut, paths, c.dataType)
        t.Logf("GetRequest:\n%v", getRequest)

        // Send Get request using the raw gNMI client.
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

        // Validate GET response.
        notifs := getResp.GetNotification()
        if len(notifs) != 1 {
                t.Fatalf("got %d notifications, want 1", len(notifs))
        }
        // Expect an empty subtree and zero updates in the notification response.
        if updates := notifs[0].GetUpdate(); len(updates) != 0 {
                t.Fatalf("Expected 0 updates, got (%v) updates", len(updates))
        }
}

// Test for gNMI Get for Data Type for non-leaf path when non-empty subtree is returned.
func (c getDataTypeTest) dataTypeForNonLeafNonEmpty(t *testing.T) {
        t.Helper()
        defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Create Get Request.
        sPath, err := ygot.StringToStructuredPath(c.reqPath)
        if err != nil {
                t.Fatalf("Unable to convert string to path (%v)", err)
        }
        paths := []*gpb.Path{sPath}
        getRequest := createGetRequest(dut, paths, c.dataType)
        t.Logf("GetRequest:\n%v", getRequest)

        // Send Get request using the raw gNMI client.
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

        // Validate GET response.
        want, ok := c.wantVal.(string)
        if !ok {
                t.Fatalf("Error with interface to string conversion (%v)", c.wantVal)
        }

        notifs := getResp.GetNotification()
        if len(notifs) != 1 {
                t.Fatalf("got %d notifications, want 1", len(notifs))
        }
        notif, updates := notifs[0], notifs[0].GetUpdate()
        if len(updates) == 0 {
                t.Fatalf("got %d updates in the notification, want >= 1", len(updates))
        }
        pathStr, err := ygot.PathToString(&gpb.Path{Elem: notif.GetPrefix().GetElem()})
        if err != nil {
                t.Fatalf("failed to convert elems (%v) to string: %v", notif.GetPrefix().GetElem(), err)
        }

        for _, update := range updates {
                updatePath, err := ygot.PathToString(update.GetPath())
                if err != nil {
                        t.Fatalf("failed to convert path to string (%v): %v", updatePath, err)
                }
                fullPath := updatePath
                if pathStr != "/" {
                        fullPath = pathStr + updatePath
                }
                if !strings.HasPrefix(fullPath, want) {
                        t.Fatalf("path compare failed to match; got (%v), want prefix (%v)", fullPath, want)
                }
        }
}

func containsOneOfTheseSubstrings(haystack string, needles []string) bool {
        for i := range needles {
                if strings.Contains(haystack, needles[i]) {
                        return true
                }
        }
        return false
}

// Test for gNMI Get for Data Type for root path when non-empty subtree is returned.
func (c getDataTypeTest) dataTypeForRootNonEmpty(t *testing.T) {
        t.Helper()
        defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        var paths []*gpb.Path
        getRequest := createGetRequest(dut, paths, c.dataType)
        t.Logf("GetRequest:\n%v", getRequest)

        // Send Get request using the raw gNMI client.
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        getResp, err := gnmiClient.Get(ctx, getRequest)
        if err != nil {
                t.Fatalf("(%v): Error while calling Get Raw API: (%v)", "dataTypeForRootNonEmpty", err)
        }
        t.Logf("GetResponse:\n%v", getResp)

        // Validate GET response.
        notifs := getResp.GetNotification()
        if len(notifs) < 6 {
                t.Fatalf("(%v): for path(%v) and type(%v), got %d notifications, want >= 6",
                        "dataTypeForRootNonEmpty", c.reqPath, c.dataType, len(notifs))
        }
        wantVal, ok := c.wantVal.([]string)
        if !ok {
                t.Fatalf("(%v): Error with interface to map conversion (%v)", "dataTypeForRootNonEmpty", c.wantVal)
        }
        for u := range notifs {
                updates := notifs[u].GetUpdate()
                if len(updates) == 0 {
                        continue
                }
                for _, update := range updates {
                        updatePath, err := ygot.PathToString(update.GetPath())
                        if err != nil {
                                t.Fatalf("(%v): failed to convert path (%v) to string (%v): %v", "dataTypeForRootNonEmpty", updatePath, prototext.Format(update), err)
                        }
                        if containsOneOfTheseSubstrings(updatePath, ignorePaths) {
                                continue
                        }
                        if !containsOneOfTheseSubstrings(updatePath, wantVal) {
                                if c.wantNotVal != "" && strings.Contains(updatePath, c.wantNotVal) {
                                        t.Fatalf("(%v): path compare failed to match; got (%v), want contains (%v)", "dataTypeForRootNonEmpty", updatePath, c.wantNotVal)
                                }
                        }
                }
        }
}

func notificationsFromGetRequest(t *testing.T, dut *ondatra.DUTDevice, getRequest *gpb.GetRequest) ([]*gpb.Notification, error) {
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        getResp, err := gnmiClient.Get(ctx, getRequest)
        if err != nil {
                return nil, err
        }
        return getResp.GetNotification(), nil
}

// Test for gNMI Get for Data Type for root path when non-empty subtree is returned.
func (c getDataTypeTest) operationalUpdateNotInConfigCheck(t *testing.T) {
        t.Helper()
        defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        var paths []*gpb.Path
        if c.reqPath != "/" {
                sPath, err := ygot.StringToStructuredPath(c.reqPath)
                if err != nil {
                        t.Fatalf("Unable to convert string to path (%v)", err)
                }
                paths = []*gpb.Path{sPath}
        }
        configNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_CONFIG))
        if err != nil {
                t.Fatalf(err.Error())
        }
        operNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_OPERATIONAL))
        if err != nil {
                t.Fatalf(err.Error())
        }

        if len(operNotifs) < 1 {
                t.Fatalf("(%v): for path(%v) and type(%v), got %d notifications, want >= 1",
                        "operationalForRootNonEmpty", c.reqPath, gpb.GetRequest_OPERATIONAL, len(operNotifs))
        }

        // Build a set from the config updates
        configUpdatesSet := make(map[string]bool)
        for u := range configNotifs {
                updates := configNotifs[u].GetUpdate()
                if len(updates) == 0 {
                        continue
                }
                for _, update := range updates {
                        updatePath, err := ygot.PathToString(update.GetPath())
                        if err != nil {
                                t.Fatalf("(%v): failed to convert path (%v) to string (%v): %v", "operationalRootCheck", updatePath, prototext.Format(update), err)
                        }
                        configUpdatesSet[updatePath] = true
                }
        }

        // Check for operational update leaves that have a corresponding config update, none should exist
        for u := range operNotifs {
                updates := operNotifs[u].GetUpdate()
                if len(updates) == 0 {
                        continue
                }
                for _, update := range updates {
                        updatePath, err := ygot.PathToString(update.GetPath())
                        if err != nil {
                                t.Fatalf("(%v): failed to convert path (%v) to string (%v): %v", "operationalRootCheck", updatePath, prototext.Format(update), err)
                        }
                        if strings.Contains(updatePath, "\\state\\") {
                                operPathAsConfig := strings.Replace(updatePath, "\\state\\", "\\config\\", 1)
                                if _, ok := configUpdatesSet[operPathAsConfig]; ok {
                                        t.Fatalf("(%v): Found operational update with a corresponding config update: (%v)", "operationalRootCheck", updatePath)
                                }
                        }
                }
        }
}

// Helper function to create and validate the GET request.
func createAndValidateLeafRequest(t *testing.T, dut *ondatra.DUTDevice, paths []*gpb.Path, dataType gpb.GetRequest_DataType, wantPath string) any {
        t.Helper()
        getReq := createGetRequest(dut, paths, dataType)
        // Send Get request using the raw gNMI client.
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        getResp, err := gnmiClient.Get(ctx, getReq)
        if err != nil {
                t.Fatalf("Error while calling Get Raw API: (%v)", err)
        }
        t.Logf("GetResponse %v for type %v", getResp, dataType)

        // Validate GET response.
        notifs := getResp.GetNotification()
        if len(notifs) != 1 {
                t.Fatalf("got %d notifications, want 1", len(notifs))
        }
        notif, updates := notifs[0], notifs[0].GetUpdate()
        if len(updates) != 1 {
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
        if gotPath != wantPath {
                t.Fatalf("got %s path, want %s path", gotPath, wantPath)
        }

        val := updates[0].GetVal()
        var gotVal any
        if val.GetJsonIetfVal() == nil {
                // Get Scalar value.
                gotVal, err = value.ToScalar(val)
                if err != nil {
                        t.Errorf("got %v, want scalar value", gotVal)
                }
        } else {
                // Unmarshal json data to container.
                if err := json.Unmarshal(val.GetJsonIetfVal(), &gotVal); err != nil {
                        t.Fatalf("could not unmarshal json data to container: %v", err)
                }
        }
        return gotVal
}

// Test for gNMI GET consistency for specified data type with ALL type at leaf level.
func (c getDataTypeTest) consistencyCheckLeafLevel(t *testing.T) {
        t.Helper()
        defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        sPath, err := ygot.StringToStructuredPath(c.reqPath)
        if err != nil {
                t.Fatalf("Unable to convert string to path (%v)", err)
        }
        paths := []*gpb.Path{sPath}
        wantVal := createAndValidateLeafRequest(t, dut, paths, gpb.GetRequest_ALL, c.reqPath)
        gotVal := createAndValidateLeafRequest(t, dut, paths, c.dataType, c.reqPath)
        if !cmp.Equal(gotVal, wantVal) {
                t.Fatalf("(consistencyCheckLeafLevel): got %v value with type %T, want %v value with type %T", gotVal, gotVal, wantVal, wantVal)
        }
        if c.dataType == gpb.GetRequest_OPERATIONAL {
                wantVal = createAndValidateLeafRequest(t, dut, paths, gpb.GetRequest_STATE, c.reqPath)
                if !cmp.Equal(gotVal, wantVal) {
                        t.Fatalf("(consistencyCheckLeafLevel): got %v value with type %T, want %v value with type %T", gotVal, gotVal, wantVal, wantVal)
                }
        }
}

// Helper function to create and validate the GET request for subtrees.
func createAndValidateSubtreeRequest(t *testing.T, dut *ondatra.DUTDevice, paths []*gpb.Path, dataType gpb.GetRequest_DataType, wantPath string) []*gpb.Update {
        t.Helper()
        getReq := createGetRequest(dut, paths, dataType)
        // Send Get request using the raw gNMI client.
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        getResp, err := gnmiClient.Get(ctx, getReq)
        if err != nil {
                t.Fatalf("Error while calling Get Raw API: (%v)", err)
        }
        t.Logf("GetResponse %v for type %v", getResp, dataType)

        // Validate GET response.
        notifs := getResp.GetNotification()
        if len(notifs) != 1 {
                t.Fatalf("got %d notifications, want 1", len(notifs))
        }
        updates := notifs[0].GetUpdate()
        if len(updates) == 0 {
                t.Fatalf("got %d updates in the notification, want >= 1", len(updates))
        }
        return updates
}

// Test for gNMI GET consistency for specified data type with ALL type at subtree level.
func (c getDataTypeTest) consistencyCheckSubtreeLevel(t *testing.T) {
        t.Helper()
        defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        sPath, err := ygot.StringToStructuredPath(c.reqPath)
        if err != nil {
                t.Fatalf("Unable to convert string to path (%v)", err)
        }
        paths := []*gpb.Path{sPath}
        wantVal := createAndValidateSubtreeRequest(t, dut, paths, gpb.GetRequest_ALL, c.reqPath)
        gotVal := createAndValidateSubtreeRequest(t, dut, paths, c.dataType, c.reqPath)
        sortProtos := cmpopts.SortSlices(func(m1, m2 *gpb.Update) bool { return m1.String() < m2.String() })
        if diff := cmp.Diff(wantVal, gotVal, protocmp.Transform(), sortProtos); diff != "" {
                t.Fatalf("(consistencyCheckSubtreeLevel) diff (-want +got):\n%s", diff)
        }
}

// This test exposes an issue with /system/mount-points paths
func TestGetAllEqualsConfigStateOperationalWithRoot(t *testing.T) {
        t.Skip("This isn't a tracked test, but it reveals behavior that requires additional investigation")
        var paths []*gpb.Path
        verifyGetAllEqualsConfigStateOperational(t, "--Not currently a tracked test--", paths)
}

func TestGetAllEqualsConfigStateOperational(t *testing.T) {
        sPath, err := ygot.StringToStructuredPath("/interfaces/")
        if err != nil {
                t.Fatalf("Unable to convert string to path (%v)", err)
        }
        verifyGetAllEqualsConfigStateOperational(t, "f49b3091-97d9-4bf0-b82d-712acf7ffba8", []*gpb.Path{sPath})
}

func verifyGetAllEqualsConfigStateOperational(t *testing.T, tid string, paths []*gpb.Path) {
        defer testhelper.NewTearDownOptions(t).WithID(tid).Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        csoPathsSet := make(map[string]bool)
        allPathsSet := make(map[string]bool)

        configNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_CONFIG))
        if err != nil {
                t.Fatalf(err.Error())
        }
        stateNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_STATE))
        if err != nil {
                t.Fatalf(err.Error())
        }
        operNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_OPERATIONAL))
        if err != nil {
                t.Fatalf(err.Error())
        }
        allNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_ALL))
        if err != nil {
                t.Fatalf(err.Error())
        }

        // Build a set from the config, state, and operational updates
        for _, notifs := range [][]*gpb.Notification{configNotifs, stateNotifs, operNotifs} {
                for _, notif := range notifs {
                        updates := notif.GetUpdate()
                        if len(updates) == 0 {
                                continue
                        }
                        for _, update := range updates {
                                updatePath, err := ygot.PathToString(update.GetPath())
                                if err != nil {
                                        t.Fatalf("(%v): failed to convert path (%v) to string (%v): %v", t.Name(), updatePath, prototext.Format(update), err)
                                }
                                csoPathsSet[updatePath] = true
                        }
                }
        }
        // Build a set from the all updates
        for _, notif := range allNotifs {
                updates := notif.GetUpdate()
                if len(updates) == 0 {
                        continue
                }
                for _, update := range updates {
                        updatePath, err := ygot.PathToString(update.GetPath())
                        if err != nil {
                                t.Fatalf("(%v): failed to convert path (%v) to string (%v): %v", t.Name(), updatePath, prototext.Format(update), err)
                        }
                        allPathsSet[updatePath] = true
                }
        }

        // Check that ALL update leaves that are present in the CSO updates, and vice versa
        // Filter out `process` updates as they are too volatile.
        var missesFromCSO []string
        for path := range allPathsSet {
                if _, ok := csoPathsSet[path]; !ok {
                        missesFromCSO = append(missesFromCSO, path)
                }
        }
        var missesFromAll []string
        for path := range csoPathsSet {
                if _, ok := allPathsSet[path]; !ok {
                        missesFromAll = append(missesFromAll, path)
                }
        }
        if len(missesFromCSO) > 0 || len(missesFromAll) > 0 {
                t.Fatalf("(%v): Found %v ALL updates missing from CSO updates set:\n%v\n\nFound %v CSO updates missing from ALL updates set:\n%v", t.Name(), len(missesFromCSO), missesFromCSO, len(missesFromAll), missesFromAll)
        }
}

func TestGetConsistencyOperationalSubtree(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("b3bc19aa-defe-41be-8344-9ad30460136f").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        sPath, err := ygot.StringToStructuredPath(fmt.Sprintf(compStatePath, "os0"))
        if err != nil {
                t.Fatalf("Unable to convert string to path (%v)", err)
        }
        paths := []*gpb.Path{sPath}

        stateNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_STATE))
        if err != nil {
                t.Fatalf(err.Error())
        }
        operNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_OPERATIONAL))
        if err != nil {
                t.Fatalf(err.Error())
        }
        allNotifs, err := notificationsFromGetRequest(t, dut, createGetRequest(dut, paths, gpb.GetRequest_ALL))
        if err != nil {
                t.Fatalf(err.Error())
        }

        // Build sets from both the STATE and ALL notifications
        updateSetSlice := make([]map[string]bool, 2)
        for i, notifs := range [][]*gpb.Notification{stateNotifs, allNotifs} {
                updateSetSlice[i] = make(map[string]bool)
                for _, notif := range notifs {
                        updates := notif.GetUpdate()
                        if len(updates) == 0 {
                                continue
                        }
                        for _, update := range updates {
                                updateSetSlice[i][update.String()] = true
                        }
                }
        }
        // Confirm that every OPERATIONAL update is present in both STATE/ALL updates
        var misses []string
        for i := range updateSetSlice {
                for _, notif := range operNotifs {
                        updates := notif.GetUpdate()
                        if len(updates) == 0 {
                                continue
                        }
                        for _, update := range updates {
                                if _, ok := updateSetSlice[i][update.String()]; !ok {
                                        misses = append(misses, update.String())
                                }
                        }
                }
        }
        if len(misses) > 0 {
                t.Fatalf("(%v): Found %v OPER updates missing:\n%v", t.Name(), len(misses), misses)
        }
}

func TestGetInvalidLeaves(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("7e81cbdf-a113-47a4-851c-1df917646c01").Teardown(t)
        dut := ondatra.DUT(t, "DUT")
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        types := []gpb.GetRequest_DataType{gpb.GetRequest_STATE, gpb.GetRequest_CONFIG, gpb.GetRequest_OPERATIONAL, gpb.GetRequest_ALL}
        invalidPaths := []string{
                "/interfaces/interface[name=%s]/config/fake-leaf",
                "/interfaces/interface[name=%s]/state/fake-leaf",
                "/interfaces/interface[name=%s]/state/counters/fake-counter",
                "/interfaces/interface[name=%s]/state/fake-leaf"}
        if len(types) != len(invalidPaths) {
                t.Fatalf("types and invalidPaths should be the same size")
        }
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        for i := range invalidPaths {
                sPath, err := ygot.StringToStructuredPath(fmt.Sprintf(invalidPaths[i], intf))
                if err != nil {
                        t.Fatalf("Unable to convert string to path (%v)", err)
                }
                paths := []*gpb.Path{sPath}
                if _, err := gnmiClient.Get(ctx, createGetRequest(dut, paths, types[i])); err == nil {
                        t.Fatalf("Expected an error with this invalid path(%v)", invalidPaths[i])
                }
        }
}

func TestGetInvalidTypesReturnError(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("5a46b9d1-9f9a-4567-a852-93eb2548f3f6").Teardown(t)
        dut := ondatra.DUT(t, "DUT")
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        types := []gpb.GetRequest_DataType{4, 5, 6, 7}
        validPaths := []string{
                "/interfaces/interface[name=%s]/config",
                "/interfaces/interface[name=%s]/state",
                "/interfaces/interface[name=%s]/state/counters",
                "/interfaces/interface[name=%s]/state"}
        if len(types) != len(validPaths) {
                t.Fatalf("types and invalidPaths should be the same size")
        }
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        for i := range validPaths {
                path := fmt.Sprintf(validPaths[i], intf)
                sPath, err := ygot.StringToStructuredPath(path)
                if err != nil {
                        t.Fatalf("Unable to convert string to path (%v)", err)
                }
                paths := []*gpb.Path{sPath}

                if _, err := gnmiClient.Get(ctx, createGetRequest(dut, paths, types[i])); err == nil {
                        t.Fatalf("No error received for Get with invalid type. Expected an error with invalid type (%v) for path (%v)", types[i], path)
                }
        }
}

func TestMissingTypeAssumesAll(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("1f3f5692-47a6-4c47-ac05-96d705752883").Teardown(t)
        dut := ondatra.DUT(t, "DUT")
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        types := []gpb.GetRequest_DataType{4, 5, 6, 7}
        validPaths := []string{
                "/interfaces/interface[name=%s]/config",
                "/interfaces/interface[name=%s]/state",
                "/interfaces/interface[name=%s]/state/counters",
                "/interfaces/interface[name=%s]/state"}
        if len(types) != len(validPaths) {
                t.Fatalf("types and invalidPaths should be the same size")
        }
        for i := range validPaths {
                path := fmt.Sprintf(validPaths[i], intf)
                sPath, err := ygot.StringToStructuredPath(path)
                if err != nil {
                        t.Fatalf("Unable to convert string to path (%v)", err)
                }
                paths := []*gpb.Path{sPath}

                // Get notifications from a Get request without an explicit type specified
                prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
                notifs, err := notificationsFromGetRequest(t, dut,
                        &gpb.GetRequest{
                                Prefix: prefix,
                                Path:   paths,
                                // Type: OMITED
                                Encoding: gpb.Encoding_PROTO,
                        })
                if err != nil {
                        t.Fatalf(err.Error())
                }

                // Verify response completeness
                i := 0
                for _, notif := range notifs {
                        pathRootStr, err := ygot.PathToString(&gpb.Path{Elem: notif.GetPrefix().GetElem()})
                        if err != nil {
                                t.Fatalf("failed to convert elems (%v) to string: %v", notif.GetPrefix().GetElem(), err)
                        }
                        updates := notif.GetUpdate()
                        if len(updates) == 0 {
                                continue
                        }
                        for _, update := range updates {
                                updatePath, err := ygot.PathToString(update.GetPath())
                                if err != nil {
                                        t.Fatalf("(%v): failed to convert path (%v) to string (%v): %v", t.Name(), updatePath, prototext.Format(update), err)
                                }
                                fullPath := pathRootStr + updatePath
                                if !strings.HasPrefix(fullPath, path) {
                                        t.Fatalf("(%v): Expected path (%v) to have prefix(%v)", t.Name(), fullPath, path)
                                }
                                i++
                        }
                        if i == 0 {
                                t.Fatalf("(%v): No updates returned for path (%v)", t.Name(), path)
                        }
                }
        }
}

package gnmi_get_modes_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/gnmi/value"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ygot/ygot"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"google.golang.org/grpc"

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
        defer esthelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
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

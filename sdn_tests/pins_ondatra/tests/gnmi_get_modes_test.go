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

func containsOneOfTheseSubstrings(haystack string, needles []string) bool {
	for i := range needles {
		if strings.Contains(haystack, needles[i]) {
			return true
		}
	}
	return false
}

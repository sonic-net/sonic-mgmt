package gnmi_stress_helper

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"google.golang.org/grpc"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
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

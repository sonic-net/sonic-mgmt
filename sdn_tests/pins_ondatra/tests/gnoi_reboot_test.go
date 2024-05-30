package gnoi_reboot_test

// This suite of tests is to end-to-end test the gNOI reboot.

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	syspb "github.com/openconfig/gnoi/system"
)

type grpcErr struct {
	code codes.Code
	desc string
}

func extractCanonicalCodeString(e error) string {
	if e == nil {
		return codes.OK.String()
	}
	re := regexp.MustCompile(`code = (\w+)`)
	match := re.FindStringSubmatch(e.Error())
	if len(match) < 2 {
		return codes.Unknown.String()
	}
	return match[1]
}

func (e *grpcErr) Error() string {
	if e == nil {
		return ""
	}
	return "rpc error: code = " + e.code.String() + " desc = " + e.desc
}

func (e *grpcErr) Is(o error) bool {
	if e == nil || o == nil {
		return e == o
	}

	if extractCanonicalCodeString(o) != e.code.String() {
		return false
	}
	if !strings.Contains(o.Error(), e.desc) {
		return false
	}
	return true
}

var (
	errStrRebootRPC       = "reboot RPC failed: rpc error: "
	errInvalidRequest     = grpcErr{code: codes.InvalidArgument, desc: "Invalid request"}
	errHostService        = grpcErr{code: codes.Internal, desc: "Internal SONiC HostService failure: "}
	errMethodNotSupported = grpcErr{code: codes.InvalidArgument, desc: "reboot method is not supported"}
)

// attainGnoiStateParams specify the parameters used by attainGnoiStateDuringReboot.
type attainGnoiStateParams struct {
	waitTime         time.Duration
	checkInterval    time.Duration
	timeBeforeReboot int64
	gnoiReachability bool
}

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
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

// Helper function to get bootTime from chassis using a raw gNMI client: the intention is to not fatally
// fail is the chassis is unreachable.
// Return boot-time, true, nil if boot-time successfully retrieved from the switch.
// Return 0, false, nil if unable to retrieve boot-time.
// Return 0, false, error if an error occurred while retrieving boot-time.
func retrieveBootTime(t *testing.T, d *ondatra.DUTDevice) (uint64, bool, error) {
	operStatusPath := gnmi.OC().System().BootTime().State().PathStruct()
	resolvedPath, _, _ := ygnmi.ResolvePath(operStatusPath)
	paths := []*gpb.Path{resolvedPath}
	getRequest := createGetRequest(d, paths, gpb.GetRequest_STATE)
	ctx := context.Background()
	gnmiClient, err := d.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}
	getResp, err := gnmiClient.Get(ctx, getRequest)

	if err != nil {
		// The inability to retrieve boot-time is not a fatal error and is an expected side effect
		// of rebooting during reboot test.
		t.Logf("error retrieving boot-time, err = (%v)", err)
		return 0, false, nil
	}
	if getResp == nil {
		return 0, false, errors.Errorf("retrieveBootTime: Get response is nil")
	}

	notifs := getResp.GetNotification()
	if len(notifs) != 1 {
		return 0, false, errors.Errorf("retrieveBootTime: There should only be one notification: getResp = (%v)", getResp)
	}

	update := notifs[0].GetUpdate()
	if len(update) != 1 {
		return 0, false, errors.Errorf("retrieveBootTime: There should only be one update: getResp = (%v)", getResp)
	}

	bootTime := update[0].GetVal()
	if bootTime == nil {
		return 0, false, errors.Errorf("retrieveBootTime: Unable to GetVal from update: getResp = (%v)", getResp)
	}
	return bootTime.GetUintVal(), true, nil
}

// attainGnoiStateDuringReboot polls the gNOI server and achieve the corresponding gNOI state depending on gnoiReachability during reboot
// If gnoiReachability is true, then this function will poll for gNOI server to be reachable and verifies the reboot.
// If gnoiReachability is false, then this function will poll for gNOI server to be unreachable and returns.
func attainGnoiStateDuringReboot(t *testing.T, d *ondatra.DUTDevice, params attainGnoiStateParams) error {
	t.Helper()
	t.Logf("Polling gNOI server reachability in %v intervals for max duration of %v", params.checkInterval, params.waitTime)
	for timeout := time.Now().Add(params.waitTime); time.Now().Before(timeout); {
		// The switch backend might not have processed the reboot request or might take
		// sometime to execute the request. So wait for check interval time and
		// later verify that the switch rebooted within the specified wait time.
		time.Sleep(params.checkInterval)
		timeElapsed := (time.Now().UnixNano() - params.timeBeforeReboot) / int64(time.Second)

		// An error returned by GNOIAble indicates we were unable to connect to the server.
		gnoiErr := testhelper.GNOIAble(t, d)

		// Treat a non GNOIAble switch and an inability to query boot-time as a server not up condition.
		if gnoiErr != nil {
			t.Logf("gNOI server not up after %v seconds", timeElapsed)
			if !params.gnoiReachability {
				return nil
			}
			continue
		}

		// An error returned by retrieveBootTime is a processing error to be treated as fatal.
		bootTime, valid, bootErr := retrieveBootTime(t, d)

		if bootErr != nil {
			return bootErr
		}

		if !valid {
			t.Logf("gNOI server not up after %v seconds", timeElapsed)
			if !params.gnoiReachability {
				return nil
			}
			continue
		}

		t.Logf("gNOI server up after %v seconds", timeElapsed)

		// An extra check to ensure that the system has rebooted.
		if bootTime < uint64(params.timeBeforeReboot) {
			t.Logf("Switch has not rebooted after %v seconds", timeElapsed)
			continue
		}

		t.Logf("Switch rebooted after %v seconds", timeElapsed)
		if !params.gnoiReachability {
			return errors.Errorf("failed to reach gNOI unreachability")
		}
		return nil
	}
	return errors.Errorf("failed to reboot")
}

func TestRebootSuccess(t *testing.T) {
	// Validation for success of reboot after sending Reboot RPC.
	ttID := "0dedda87-1b76-40a2-8712-24c1579987ee"
	defer testhelper.NewTearDownOptions(t).WithID(ttID).Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	waitTime, err := testhelper.RebootTimeForDevice(t, dut)
	if err != nil {
		t.Fatalf("Unable to get reboot wait time: %v", err)
	}
	params := testhelper.NewRebootParams().WithWaitTime(waitTime).WithCheckInterval(30*time.Second).WithRequest(syspb.RebootMethod_COLD).WithLatencyMeasurement(ttID, "gNOI Reboot With Type: "+syspb.RebootMethod_COLD.String())
	if err := testhelper.Reboot(t, dut, params); err != nil {
		t.Fatalf("Failed to reboot DUT: %v", err)
	}
}

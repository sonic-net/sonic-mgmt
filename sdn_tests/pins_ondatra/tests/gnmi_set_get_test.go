package gnmi_set_get_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/testt"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/prototext"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	testdataDir = "./"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

/**********************************************************
* gNMI SET Update operations
**********************************************************/
func TestGNMISetUpdateSingleLeaf(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("ffe66b7b-0e61-49bd-803d-0406a8c914d7").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	// Add Prefix information for the GetRequest.
	prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

	// Select a random front panel interface EthernetX.
	intf, err := testhelper.RandomInterface(t, dut, nil)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}

	mtuPath := gnmi.OC().Interface(intf).Mtu()
	resolvedPath, _, errs := ygnmi.ResolvePath(mtuPath.Config().PathStruct())
	if errs != nil {
		t.Fatalf("Failed to resolve path %v: %v", mtuPath, err)
	}
	mtu := gnmi.Get(t, dut, mtuPath.Config())
	// Adding 22 bytes to the existing MTU value for the test.
	newMtu := mtu + 22

	defer func() {
		// Replace the old value for the MTU field as a test cleanup.
		gnmi.Replace(t, dut, mtuPath.Config(), mtu)
		gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 5*time.Second, mtu)
	}()

	setRequest := &gpb.SetRequest{
		Prefix: prefix,
		Update: []*gpb.Update{{
			Path: resolvedPath,
			Val: &gpb.TypedValue{
				Value: &gpb.TypedValue_JsonIetfVal{
					JsonIetfVal: []byte(strconv.FormatUint(uint64(newMtu), 10)),
				},
			},
		}},
	}

	enabled := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Enabled().Config())
	ctx := context.Background()

	// Fetch raw gNMI client and call Set API to send Set Request.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}
	setResp, err := gnmiClient.Set(ctx, setRequest)
	if err != nil {
		t.Fatalf("Unable to fetch set client (%v)", err)
	}
	t.Logf("SetResponse:\n%v", setResp)

	// Verify the value is being set properly using get.
	if got := gnmi.Get(t, dut, mtuPath.Config()); got != newMtu {
		t.Errorf("MTU matched failed! got:%v, want:%v", got, newMtu)
	}

	// Verify that other leaf nodes are not changed.
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Enabled().Config()); got != enabled {
		t.Errorf("Enabled matched failed! got:%v, want:%v", got, enabled)
	}
}

func TestGNMISetUpdateNonExistingLeaf(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("408e875e-d00f-4071-acaf-204616800bee").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	// Add Prefix information for the GetRequest.
	prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

	// Select a random front panel interface EthernetX.
	intf, err := testhelper.RandomInterface(t, dut, nil)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}

	res := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
	descPath := gnmi.OC().Interface(intf).Description()
	resolvedPath, _, errs := ygnmi.ResolvePath(descPath.Config().PathStruct())
	if errs != nil {
		t.Fatalf("Failed to resolve path %v: %v", descPath, errs)
	}
	ctx := context.Background()
	var desc string = "description before reset"
	var descExist bool = false
	if res.Description != nil {
		desc = *res.Description
		descExist = true
		var paths []*gpb.Path
		paths = append(paths, resolvedPath)

		delRequest := &gpb.SetRequest{
			Prefix: prefix,
			Delete: paths,
		}
		// Fetch raw gNMI client and call Set API to send Set Request.
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		delResp, err := gnmiClient.Set(ctx, delRequest)
		if err != nil {
			t.Fatalf("Unable to fetch set delete client (%v)", err)
		}
		t.Logf("SetResponse:\n%v", delResp)
	}

	wantDesc := "description after reset"
	defer func() {
		// Replace the id to original value if it exists before the test.
		if descExist {
			gnmi.Delete(t, dut, descPath.Config())
			gnmi.Replace(t, dut, descPath.Config(), desc)
			gnmi.Await(t, dut, gnmi.OC().Interface(intf).Description().State(), 5*time.Second, desc)
		}
	}()

	setRequest := &gpb.SetRequest{
		Prefix: prefix,
		Update: []*gpb.Update{{
			Path: resolvedPath,
			Val: &gpb.TypedValue{
				Value: &gpb.TypedValue_JsonIetfVal{
					JsonIetfVal: []byte(fmt.Sprintf("\"%s\"", wantDesc)),
				},
			},
		}},
	}

	mtu := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config())

	// Fetch raw gNMI client and call Set API to send Set Request.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(context.Background(), grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}
	setResp, err := gnmiClient.Set(ctx, setRequest)
	if err != nil {
		t.Fatalf("Unable to fetch set client (%v)", err)
	}
	t.Logf("SetResponse:\n%v", setResp)
	// Verify the value is being set properly using get.
	if got := gnmi.Get(t, dut, descPath.Config()); got != wantDesc {
		t.Errorf("ID matched failed! got:%v, want: description after reset", got)
	}
	// Verify that other leaf nodes are not changed.
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config()); got != mtu {
		t.Errorf("MTU matched failed! mtuAfterSet:%v, want:%v", got, mtu)
	}
}

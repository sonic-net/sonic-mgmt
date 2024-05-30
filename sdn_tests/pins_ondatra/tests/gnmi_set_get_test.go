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

func TestGNMISetUpdateMultipleLeafs(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("fc046164-bd3f-44f5-8056-7ff8df404909").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Select a random front panel interface EthernetX.
	intf, err := testhelper.RandomInterface(t, dut, nil)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}

	// Get fields from interface subtree.
	res := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
	descPath := gnmi.OC().Interface(intf).Description()
	resolvedDescPath, _, errs := ygnmi.ResolvePath(descPath.Config().PathStruct())
	if errs != nil {
		t.Fatalf("Failed to resolve path %v: %v", descPath, err)
	}
	var desc string
	desExist := false

	if res.Description != nil {
		desc = *res.Description
		desExist = true
	}

	mtuPath := gnmi.OC().Interface(intf).Mtu()
	resolvedMtuPath, _, errs := ygnmi.ResolvePath(mtuPath.Config().PathStruct())
	if errs != nil {
		t.Fatalf("Failed to resolve path %v: %v", mtuPath, err)
	}
	mtu := res.GetMtu()
	// Adding 22 bytes to the existing MTU value for the test.
	wantMtu := mtu + 22
	wantDesc := "This is a wanted description."
	enabled := res.GetEnabled()
	id := res.GetId()
	fqin := testhelper.FullyQualifiedInterfaceName(t, dut, intf)

	// Add Prefix information for the GetRequest.
	prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

	defer func() {
		// Replace the old values for test cleanup.
		gnmi.Replace(t, dut, mtuPath.Config(), mtu)
		gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 5*time.Second, mtu)
		if desExist {
			gnmi.Replace(t, dut, descPath.Config(), desc)
			gnmi.Await(t, dut, gnmi.OC().Interface(intf).Description().State(), 5*time.Second, desc)
		} else {
			delRequest := &gpb.SetRequest{
				Prefix: prefix,
				Delete: []*gpb.Path{resolvedDescPath},
			}
			ctx := context.Background()
			gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
			if err != nil {
				t.Fatalf("Unable to get gNMI client (%v)", err)
			}
			if _, err := gnmiClient.Set(ctx, delRequest); err != nil {
				t.Fatalf("Unable to fetch set delete client (%v)", err)
			}
		}
	}()

	setRequest := &gpb.SetRequest{
		Prefix: prefix,
		Update: []*gpb.Update{
			{
				Path: resolvedMtuPath,
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: []byte(strconv.FormatUint(uint64(wantMtu), 10)),
					},
				},
			},
			{
				Path: resolvedDescPath,
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: []byte(fmt.Sprintf("\"%s\"", wantDesc)),
					},
				},
			},
		},
	}

	// Fetch raw gNMI client and call Set API to send Set Request.
	ctx := context.Background()
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}
	setResp, err := gnmiClient.Set(ctx, setRequest)
	if err != nil {
		t.Fatalf("Error while calling Set Raw API: (%v)", err)
	}
	t.Logf("SetResponse:\n%v", setResp)

	// Verify the values are set properly using get.
	// Get fields from interface subtree.
	intfAfterSet := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
	if got := intfAfterSet.GetMtu(); got != wantMtu {
		t.Errorf("MTU match failed! got: %v, want: %v", got, wantMtu)
	}
	if got := intfAfterSet.GetDescription(); got != wantDesc {
		t.Errorf("Description match failed! got: %v, want: %v", got, wantDesc)
	}

	// Verify that other leaf nodes are not changed.
	if got := intfAfterSet.GetEnabled(); got != enabled {
		t.Errorf("Enabled match failed! got %v, want %v", got, enabled)
	}
	if got := intfAfterSet.GetId(); got != id {
		t.Errorf("ID match failed! got %v, want %v", got, id)
	}
	if got := testhelper.FullyQualifiedInterfaceName(t, dut, intf); got != fqin {
		t.Errorf("FullyQualifiedInterfaceName match failed! got %v, want %v", got, fqin)
	}
}

func TestGNMISetUpdateInvalidDataLeaf(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("6dc4b8de-f5d8-406d-b9c1-9530eecefd3b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	// Add Prefix information for the GetRequest.
	prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

	path := &gpb.Path{Elem: []*gpb.PathElem{{Name: "platform"}}}
	setRequest := &gpb.SetRequest{
		Prefix: prefix,
		Update: []*gpb.Update{{
			Path: path,
			Val: &gpb.TypedValue{
				Value: &gpb.TypedValue_JsonIetfVal{
					JsonIetfVal: []byte("{\"openconfig-interfaces:description:\":\"test\"}"),
				},
			},
		}},
	}

	// Fetch raw gNMI client and call Set API to send Set Request.
	ctx := context.Background()
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}
	if _, err := gnmiClient.Set(ctx, setRequest); err == nil {
		t.Fatalf("Set request is expected to fail but it didn't")
	}
}

func TestGNMISetUpdateInvalidLeaf(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("6dcd41e7-a491-4d71-a52a-0ea4f446400a").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	// Add Prefix information for the GetRequest.
	prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

	// Select a random front panel interface EthernetX.
	intf, err := testhelper.RandomInterface(t, dut, nil)
	if err != nil {
		t.Fatalf("Failed to fetch random interface: %v", err)
	}

	path := &gpb.Path{Elem: []*gpb.PathElem{{Name: "interfaces"}, {Name: "interface", Key: map[string]string{"name": intf}}, {Name: "config"}, {Name: "xyz"}}}
	setRequest := &gpb.SetRequest{
		Prefix: prefix,
		Update: []*gpb.Update{{
			Path: path,
			Val: &gpb.TypedValue{
				Value: &gpb.TypedValue_JsonIetfVal{
					JsonIetfVal: []byte("123"),
				},
			},
		}},
	}

	mtu := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config())
	ctx := context.Background()

	// Fetch raw gNMI client and call Set API to send Set Request.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}
	if _, err = gnmiClient.Set(ctx, setRequest); err == nil {
		t.Fatalf("Set request is expected to fail but it didn't")
	}

	// Verify that other leaf nodes are not changed.
	if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config()); got != mtu {
		t.Errorf("MTU matched failed! mtuAfterSet:%v, want:%v", got, mtu)
	}

}

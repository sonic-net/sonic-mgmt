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

/**********************************************************
* gNMI SET Replace operations
**********************************************************/
// Sample test that performs gNMI SET replace on leaf.
func TestGNMISetReplaceSingleLeaf(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("162ec144-03b2-45ba-8bab-975ae4d09f7a").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        enabled := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Enabled().Config())
        oldMtu := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config())
        defer func() {
                // Replace the old MTU value as a test cleanup.
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), oldMtu)
                gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 5*time.Second, oldMtu)
        }()

        // Configure port MTU and verify that state path reflects configured MTU.
        mtu := uint16(1500)
        gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), mtu)

        if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config()); got != mtu {
                t.Errorf("MTU matched failed! got:%v, want:%v", got, mtu)
        }
        // Verify that other leaf nodes are not changed.
        if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Enabled().Config()); got != enabled {
                t.Errorf("enabled matched failed! idAfterSet:%v, want:%v", got, enabled)
        }

}

func TestGNMISetReplaceMoreThanOneLeaf(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("d89eb043-3594-4265-bf91-5e71477f98b9").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        oldEnabled := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Enabled().Config())
        oldMtu := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config())
        intfType := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Type().Config())
        mtu := oldMtu + 22
        enabled := strconv.FormatBool(!oldEnabled)

        defer func() {
                // Replace the old values as a test cleanup.
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Enabled().Config(), oldEnabled)
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), oldMtu)
                // Wait for the port to be operationally up.
                gnmi.Await(t, dut.GNMIOpts().WithYGNMIOpts(ygnmi.WithSubscriptionMode(gpb.SubscriptionMode_ON_CHANGE)), gnmi.OC().Interface(intf).OperStatus().State(), 30*time.Second, oc.Interface_OperStatus_UP)
                gnmi.Await(t, dut, gnmi.OC().Interface(intf).Enabled().State(), 1*time.Second, oldEnabled)
                gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 5*time.Second, oldMtu)
        }()

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        path := &gpb.Path{Elem: []*gpb.PathElem{{Name: "interfaces"}, {Name: "interface", Key: map[string]string{"name": intf}}, {Name: "openconfig-interfaces:config"}}}
        setRequest := &gpb.SetRequest{
                Prefix: prefix,
                Replace: []*gpb.Update{{
                        Path: path,
                        Val: &gpb.TypedValue{
                                Value: &gpb.TypedValue_JsonIetfVal{
                                        JsonIetfVal: []byte("{\"enabled\":" + enabled + ",\"mtu\":" + strconv.FormatUint(uint64(mtu), 10) + "}"),
                                },
                        },
                }},
        }
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
        if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config()); got != mtu {
                t.Errorf("MTU matched failed! got:%v, want:%v", got, mtu)
        }
        if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Enabled().Config()); got == oldEnabled {
                t.Errorf("Enabled matched failed! got:%v, want:%v", got, !oldEnabled)
        }
        // Verify that other leaf nodes are not changed.
        if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Type().Config()); got != intfType {
                t.Errorf("Type matched failed! got type :%v, want:%v", got, intfType)
        }
}

func TestGNMISetReplaceInvalidDataLeaf(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("31509436-ddc5-405b-9008-0b71d28fbb92").Teardown(t)
        dut := ondatra.DUT(t, "DUT")
        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        path := &gpb.Path{Elem: []*gpb.PathElem{{Name: "platform"}}}
        setRequest := &gpb.SetRequest{
                Prefix: prefix,
                Replace: []*gpb.Update{{
                        Path: path,
                        Val: &gpb.TypedValue{
                                Value: &gpb.TypedValue_JsonIetfVal{
                                        JsonIetfVal: []byte("{\"openconfig-interfaces:description:\":\"test\"}"),
                                },
                        },
                }},
        }
        ctx := context.Background()

        // Fetch raw gNMI client and call Set API to send Set Request.
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        setResp, err := gnmiClient.Set(ctx, setRequest)
        if err == nil {
                t.Fatalf("Set request is expected to fail but it didn't")
        }
        t.Logf("SetResponse:\n%v", setResp)
}

func TestGNMISetReplaceInvalidLeaf(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("a9e707cf-4872-4066-ab38-8fe2c14af892").Teardown(t)
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
                Replace: []*gpb.Update{{
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
                t.Errorf("MTU matched failed! got:%v, want:%v", got, mtu)
        }

}

func TestGNMISetReplaceMultipleLeafsValid(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("c1f9dd81-d509-405f-bed2-e108e619b5f6").Teardown(t)
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
        var desc, wantDesc string
        descExist := false
        if res.Description != nil {
                desc = *res.Description
                descExist = true
        }
        mtuPath := gnmi.OC().Interface(intf).Mtu()
        resolvedMtuPath, _, errs := ygnmi.ResolvePath(mtuPath.Config().PathStruct())
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", mtuPath, err)
        }
        mtu := res.GetMtu()
        // Adding 22 bytes to the existing MTU value for the test.
        wantMtu := mtu + 22
        wantDesc = "wanted description"
        enabled := res.GetEnabled()
        fqin := testhelper.FullyQualifiedInterfaceName(t, dut, intf)

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        defer func() {
                // Replace the old values for test cleanup.
                gnmi.Replace(t, dut, mtuPath.Config(), mtu)
                gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 5*time.Second, mtu)
                if descExist {
                        gnmi.Replace(t, dut, descPath.Config(), desc)
                        gnmi.Await(t, dut, gnmi.OC().Interface(intf).Description().State(), 20*time.Second, desc)
                } else {
                        delRequest := &gpb.SetRequest{
                                Prefix: prefix,
                                Delete: []*gpb.Path{resolvedDescPath},
                        }
                        // Fetch set client using the raw gNMI client.
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
                Replace: []*gpb.Update{
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

        // Get fields from interface subtree.
        intfAfterSet := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
        // Verify the values are set properly using get.
        if got := intfAfterSet.GetMtu(); got != wantMtu {
                t.Errorf("MTU match failed! got: %v, want: %v", got, wantMtu)
        }
        if got := intfAfterSet.GetDescription(); got != wantDesc {
                t.Errorf("Description match failed! got %v, want %v", got, wantDesc)
        }

        // Verify that other leaf nodes are not changed.
        if got := intfAfterSet.GetEnabled(); got != enabled {
                t.Errorf("Enabled match failed! got %v, want %v", got, enabled)
        }

        if got := testhelper.FullyQualifiedInterfaceName(t, dut, intf); got != fqin {
                t.Errorf("FullyQualifiedInterfaceName match failed! got %v, want %v", got, fqin)
        }
}

func TestGNMISetReplaceMultipleLeafsInvalid(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("c485b29b-7e1e-4b5a-bccd-797ced277008").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        // Get fields from interface subtree.
        mtuPath := gnmi.OC().Interface(intf).Mtu()
        resolvedPath, _, errs := ygnmi.ResolvePath(mtuPath.Config().PathStruct())
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", mtuPath, err)
        }
        mtu := gnmi.Get(t, dut, mtuPath.Config())

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
        setRequest := &gpb.SetRequest{
                Prefix: prefix,
                Replace: []*gpb.Update{
                        {
                                Path: resolvedPath,
                                Val: &gpb.TypedValue{
                                        Value: &gpb.TypedValue_JsonIetfVal{
                                                JsonIetfVal: []byte(strconv.FormatUint(uint64(mtu+22), 10)),
                                        },
                                },
                        },
                        {
                                Path: &gpb.Path{
                                        Elem: []*gpb.PathElem{
                                                {
                                                        Name: "interfaces",
                                                },
                                                {
                                                        Name: "interface",
                                                        Key:  map[string]string{"name": intf},
                                                },
                                                {
                                                        Name: "config",
                                                },
                                                {
                                                        Name: "openconfig-abc:xyz",
                                                },
                                        },
                                },
                                Val: &gpb.TypedValue{
                                        Value: &gpb.TypedValue_JsonIetfVal{
                                                JsonIetfVal: []byte("987"),
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
        if _, err = gnmiClient.Set(ctx, setRequest); err == nil {
                t.Fatalf("Set request is expected to fail but it didn't")
        }

        // Verify that the MTU value did not get changed.
        if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config()); got != mtu {
                t.Errorf("MTU match failed! gotMtu %v, want %v", got, mtu)
        }
}

/**********************************************************
* gNMI SET Delete operations
**********************************************************/
func TestGNMISetDeleteSingleLeaf(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("01850837-93b3-44a6-9d8f-84a0bd6c8725").Teardown(t)
        dut := ondatra.DUT(t, "DUT")
        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        res := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
        desPath := gnmi.OC().Interface(intf).Description()
        resolvedPath, _, errs := ygnmi.ResolvePath(desPath.Config().PathStruct())
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", desPath, err)
        }
        ctx := context.Background()
        var des string = ""
        var desExist bool = false
        mtu := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config())
        if res.Description != nil {
                des = *res.Description
                desExist = true
        } else {
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Description().Config(), "Test description from ondatra test")
        }
        paths := []*gpb.Path{resolvedPath}

        defer func() {
                // Replace the id to original value if it exists before the test.
                if desExist {
                        gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Description().Config(), des)
                        gnmi.Await(t, dut, gnmi.OC().Interface(intf).Description().State(), 5*time.Second, des)
                }
        }()

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

        // Verify that other leaf nodes are not changed.
        if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config()); got != mtu {
                t.Errorf("MTU matched failed! got:%v, want:%v", got, mtu)
        }
}

func TestGNMISetDeleteMultipleLeafs(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("66addddd-df5d-4ff0-91ca-ff2a3582be69").Teardown(t)
        dut := ondatra.DUT(t, "DUT")
        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        res := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
        ctx := context.Background()

        descPath := gnmi.OC().Interface(intf).Description()
        resolvedDescPath, _, errs := ygnmi.ResolvePath(descPath.Config().PathStruct())
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", descPath, err)
        }
        var desc string
        descExist := false
        if res.Description != nil {
                desc = *res.Description
                descExist = true
        } else {
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Description().Config(), "desc")
        }

        defaultMtu := uint16(9100)
        mtuPath := gnmi.OC().Interface(intf).Mtu()
        resolvedMtuPath, _, errs := ygnmi.ResolvePath(mtuPath.Config().PathStruct())
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", mtuPath, err)
        }

        if res.Mtu == nil {
                t.Fatalf("MTU should not be nil!")
        }

        mtu := uint16(2123)
        nonDefaultMtu := false // Default value of MTU is 9100
        if *res.Mtu != defaultMtu {
                mtu = *res.Mtu
                nonDefaultMtu = true
        } else {
                gnmi.Update(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), mtu)
                gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 20*time.Second, mtu)
        }

        defer func() {
                // Replace the fields to original values if they existed before the test.
                if descExist {
                        gnmi.Replace(t, dut, descPath.Config(), desc)
                        gnmi.Await(t, dut, gnmi.OC().Interface(intf).Description().State(), 5*time.Second, desc)
                }
                if nonDefaultMtu {
                        gnmi.Replace(t, dut, mtuPath.Config(), mtu)
                        gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 5*time.Second, mtu)
                }
        }()

        paths := []*gpb.Path{resolvedDescPath, resolvedMtuPath}
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
                t.Fatalf("Error while calling Set Delete Raw API(%v)", err)
        }
        t.Logf("SetResponse:\n%v", delResp)

        // Verify desc leaf is deleted.
        testt.ExpectFatal(t, func(t testing.TB) {
                gnmi.Get(t, dut, descPath.Config())
        })
        // Verify MTU leaf is deleted (set to default value)
        if gotMtu := gnmi.Get(t, dut, mtuPath.Config()); gotMtu != defaultMtu {
                t.Fatalf("Default MTU matched failed! got:%v, want:%v", gotMtu, defaultMtu)
        }
}

func TestGNMISetDeleteInvalidLeaf(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("bc463964-5e63-417f-bd32-08f17faf84a3").Teardown(t)
        dut := ondatra.DUT(t, "DUT")
        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        path := &gpb.Path{Elem: []*gpb.PathElem{{Name: "interfaces"}, {Name: "interface", Key: map[string]string{"name": intf}}, {Name: "config"}, {Name: "xyz"}}}
        ctx := context.Background()
        mtu := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config())

        paths := []*gpb.Path{path}

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
        if err == nil {
                t.Fatalf("Set request is expected to fail but it didn't")
        }
        t.Logf("SetResponse:\n%v", delResp)

        // Verify that other leaf nodes are not changed.
        if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config()); got != mtu {
                t.Fatalf("MTU matched failed! got:%v, want:%v", got, mtu)
        }
}

/**********************************************************
* gNMI SET misc operations
**********************************************************/

/* Test to verify the order of SET operations in the same request.
 * Verify that specified leaf has been deleted, and other specified leafs
 * have been replaced, followed with updating of leaf values.
 */
func TestGNMISetDeleteReplaceUpdateOrderValid(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("fd8b8e2c-69dc-406c-99fd-6bdcf670e17d").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        // Get fields from interface subtree.
        res := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
        mtuPath := gnmi.OC().Interface(intf).Mtu()
        resolvedMtuPath, _, errs := ygnmi.ResolvePath(mtuPath.Config().PathStruct())
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", mtuPath, err)
        }

        mtuExist := false
        mtu := uint16(9191)
        if res.Mtu != nil {
                mtu = *res.Mtu
                mtuExist = true
        } else {
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), mtu)
        }

        descPath := gnmi.OC().Interface(intf).Description()
        resolvedDescPath, _, errs := ygnmi.ResolvePath(descPath.Config().PathStruct())
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", descPath, err)
        }
        desc := "desc"
        descExist := false
        if res.Description != nil {
                desc = *res.Description
                descExist = true
        } else {
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Description().Config(), desc)
        }

        fqinPath := fmt.Sprintf("/interfaces/interface[name=%s]/config/fully-qualified-interface-name", intf)
        resolvedFqinPath, errs := testhelper.StringToYgnmiPath(fqinPath)
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", fqinPath, err)
        }
        fqin := "FQIN"
        fqinExist := false
        if name := testhelper.FullyQualifiedInterfaceName(t, dut, intf); name != "" {
                fqin = name
                fqinExist = true
        } else {
                testhelper.ReplaceFullyQualifiedInterfaceName(t, dut, intf, fqin)
        }
        wantFqin := "testFQIN"
        wantMtu := mtu + 22

        enabled := res.GetEnabled()
        loopBack := res.GetLoopbackMode()
        name := res.GetName()

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
        defer func() {
                ctx := context.Background()
                gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
                if err != nil {
                        t.Fatalf("Unable to get gNMI client (%v)", err)
                }

                // Replace the old values for test cleanup.
                if mtuExist {
                        gnmi.Replace(t, dut, mtuPath.Config(), mtu)
                        gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 5*time.Second, mtu)
                } else {
                        delRequest := &gpb.SetRequest{
                                Prefix: prefix,
                                Delete: []*gpb.Path{resolvedMtuPath},
                        }
                        // Fetch set client using the raw gNMI client.
                        if _, err := gnmiClient.Set(ctx, delRequest); err != nil {
                                t.Fatalf("Unable to fetch set delete client (%v)", err)
                        }
                }
                if descExist {
                        gnmi.Replace(t, dut, descPath.Config(), desc)
                        gnmi.Await(t, dut, gnmi.OC().Interface(intf).Description().State(), 5*time.Second, desc)
                } else {
                        delRequest := &gpb.SetRequest{
                                Prefix: prefix,
                                Delete: []*gpb.Path{resolvedDescPath},
                        }
                        // Fetch set client using the raw gNMI client.
                        if _, err := gnmiClient.Set(ctx, delRequest); err != nil {
                                t.Fatalf("Unable to fetch set delete client (%v)", err)
                        }
                }
                if fqinExist {
                        testhelper.ReplaceFullyQualifiedInterfaceName(t, dut, intf, fqin)
                } else {
                        delRequest := &gpb.SetRequest{
                                Prefix: prefix,
                                Delete: []*gpb.Path{resolvedFqinPath},
                        }
                        // Fetch set client using the raw gNMI client.
                        if _, err := gnmiClient.Set(ctx, delRequest); err != nil {
                                t.Fatalf("Unable to fetch set delete client (%v)", err)
                        }
                }
        }()

        setRequest := &gpb.SetRequest{
                Prefix: prefix,
                Delete: []*gpb.Path{resolvedMtuPath, resolvedDescPath},
                Replace: []*gpb.Update{
                        {
                                Path: resolvedMtuPath,
                                Val: &gpb.TypedValue{
                                        Value: &gpb.TypedValue_JsonIetfVal{
                                                JsonIetfVal: []byte(strconv.FormatUint(uint64(wantMtu), 10)),
                                        },
                                },
                        },
                        {
                                Path: resolvedFqinPath,
                                Val: &gpb.TypedValue{
                                        Value: &gpb.TypedValue_JsonIetfVal{
                                                JsonIetfVal: []byte("\"tempFQIN\""),
                                        },
                                },
                        },
                },
                Update: []*gpb.Update{{
                        Path: resolvedFqinPath,
                        Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte("\"" + wantFqin + "\"")}},
                }},
        }

        // Fetch raw gNMI client and call Set API to send Set Request.
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        if _, err := gnmiClient.Set(ctx, setRequest); err != nil {
                t.Fatalf("Error while calling Set Raw API: (%v)", err)
        }

        // Verify that the Description leaf is deleted.
        testt.ExpectFatal(t, func(t testing.TB) {
                gnmi.Get(t, dut, descPath.Config())
        })
        // Get fields from interface subtree.
        intfAfterSet := gnmi.Get(t, dut, gnmi.OC().Interface(intf).State())
        if got := testhelper.FullyQualifiedInterfaceName(t, dut, intf); got != wantFqin {
                t.Errorf("FullyQualifiedInterfaceName match failed! got %v, want %v", got, wantFqin)
        }
        if got := intfAfterSet.GetMtu(); got != wantMtu {
                t.Errorf("mtu match failed! got: %v, want: %v", got, wantMtu)
        }

        // Verify that other leaf nodes are not changed.
        if got := intfAfterSet.GetEnabled(); got != enabled {
                t.Errorf("enabled match failed! got %v, want %v", got, enabled)
        }
        if got := intfAfterSet.GetLoopbackMode(); got != loopBack {
                t.Errorf("loopback-mode match failed! got: %v, want: %v", got, loopBack)
        }
        if got := intfAfterSet.GetName(); got != name {
                t.Errorf("name match failed! got: %v, want: %v", got, name)
        }
}

/* Test to verify the order of SET operations in the same request.
 * Verify that the specified path has been deleted and other
 * specified path attributes have been updated. */
func TestGNMISetDeleteUpdateOrderValid(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("b7f99b79-f4fb-4c56-95be-602ad0361ec0").Teardown(t)
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
        desc := "desc"
        descExist := false
        if res.Description != nil {
                desc = *res.Description
                descExist = true
        } else {
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Description().Config(), desc)
        }
        wantDesc := "testDescription"

        enabled := res.GetEnabled()
        mtu := res.GetMtu()

        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
        defer func() {
                // Replace the old values for test cleanup.
                if descExist {
                        gnmi.Replace(t, dut, descPath.Config(), desc)
                        gnmi.Await(t, dut, gnmi.OC().Interface(intf).Description().State(), 5*time.Second, desc)
                } else {
                        delRequest := &gpb.SetRequest{
                                Prefix: prefix,
                                Delete: []*gpb.Path{resolvedDescPath},
                        }
                        // Fetch set client using the raw gNMI client.
                        if _, err := gnmiClient.Set(ctx, delRequest); err != nil {
                                t.Fatalf("Unable to fetch set delete client (%v)", err)
                        }
                }
        }()

        setRequest := &gpb.SetRequest{
                Prefix: prefix,
                Delete: []*gpb.Path{resolvedDescPath},
                Update: []*gpb.Update{{
                        Path: resolvedDescPath,
                        Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte("\"" + wantDesc + "\"")}},
                }},
        }

        // Fetch raw gNMI client and call Set API to send Set Request.
        if _, err := gnmiClient.Set(ctx, setRequest); err != nil {
                t.Fatalf("Error while calling Set Raw API: (%v)", err)
        }

        // Get fields from interface subtree.
        intfAfterSet := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
        if got := intfAfterSet.GetDescription(); got != wantDesc {
                t.Errorf("Description match failed! got %v, want %v", got, wantDesc)
        }

        // Verify that other leaf nodes are not changed.
        if got := intfAfterSet.GetEnabled(); got != enabled {
                t.Errorf("Enabled match failed! got %v, want %v", got, enabled)
        }
        if got := intfAfterSet.GetMtu(); got != mtu {
                t.Errorf("MTU match failed! got: %v, want: %v", got, mtu)
        }
}

/* Test to verify the order of SET operations in the same request.
 * Verify that with delete followed by update in same SET Request,
 * an error message related to the invalid update is returned. */
func TestGNMISetDeleteUpdateOrderInvalid(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("b43ed0ae-22c2-4c25-b50a-96c7243255d9").Teardown(t)
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
        desc := "desc"
        descExist := false
        if res.Description != nil {
                desc = *res.Description
                descExist = true
        }

        enabled := res.GetEnabled()
        mtu := res.GetMtu()

        defer func() {
                // Replace the old values for test cleanup.
                if descExist {
                        gnmi.Replace(t, dut, descPath.Config(), desc)
                        gnmi.Await(t, dut, gnmi.OC().Interface(intf).Description().State(), 5*time.Second, desc)
                }
        }()

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
        setRequest := &gpb.SetRequest{
                Prefix: prefix,
                Delete: []*gpb.Path{resolvedDescPath},
                Update: []*gpb.Update{{
                        Path: resolvedDescPath,
                        Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte("123")}},
                }},
        }

        // Verify that error message is returned for invalid update request.
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        if _, err := gnmiClient.Set(ctx, setRequest); err == nil {
                t.Fatalf("Error expected while calling Set Raw API")
        }

        // Get fields from interface subtree.
        intfAfterSet := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())

        // Verify that other leaf nodes are not changed.
        if got := intfAfterSet.GetEnabled(); got != enabled {
                t.Errorf("Enabled match failed! got %v, want %v", got, enabled)
        }
        if got := intfAfterSet.GetMtu(); got != mtu {
                t.Errorf("MTU match failed! got: %v, want: %v", got, mtu)
        }
}

/* Test that performs gNMI SET for an empty path. Verify that there are no errors
 *  returned by the server and a valid response has been sent to the client,
 *  also verifies that none of the paths are changed. */
func TestGNMISetEmptyPath(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("0b2e92b0-1295-4aa7-a27d-99073c09e2b7").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }
        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
        // Get fields from interface subtree.
        intfBeforeSet := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())

        // Create setRequest message with an empty path.
        setRequest := &gpb.SetRequest{
                Prefix: prefix,
        }

        // Fetch set client using the raw gNMI client.
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        if _, err := gnmiClient.Set(ctx, setRequest); err != nil {
                t.Fatalf("Error while calling Set API with empty update: (%v)", err)
        }

        // Verify that the leaf values did not change.
        intfAfterSet := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
        cmpOptions := cmp.Options{cmpopts.IgnoreFields(oc.Interface_Ethernet{}, "Counters"),
                cmpopts.IgnoreFields(oc.Interface{}, "Counters")}
        if diff := cmp.Diff(intfBeforeSet, intfAfterSet, cmpOptions); diff != "" {
                t.Fatalf("diff (-want +got): %v", diff)
        }
}

/* Test that performs gNMI SET with two gNMI clients. */
func TestGNMIMultipleClientSet(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("753e4dfc-5dda-4bfe-8b1c-e377e6c458ad").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        mtuPath := gnmi.OC().Interface(intf).Mtu()
        resolvedMtuPath, _, errs := ygnmi.ResolvePath(mtuPath.Config().PathStruct())
        if errs != nil {
                t.Fatalf("Failed to resolve path %v: %v", mtuPath, err)
        }
        mtu := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().Config())
        defer func() {
                // Replace the old value for the MTU field as a test cleanup.
                gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), mtu)
                gnmi.Await(t, dut, gnmi.OC().Interface(intf).Mtu().State(), 5*time.Second, mtu)
        }()

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        setRequest1 := &gpb.SetRequest{
                Prefix: prefix,
                Replace: []*gpb.Update{
                        {
                                Path: resolvedMtuPath,
                                Val: &gpb.TypedValue{
                                        Value: &gpb.TypedValue_JsonIetfVal{
                                                JsonIetfVal: []byte(strconv.FormatUint(uint64(9100), 10)),
                                        },
                                },
                        },
                },
        }
        setRequest2 := &gpb.SetRequest{
                Prefix: prefix,
                Replace: []*gpb.Update{
                        {
                                Path: resolvedMtuPath,
                                Val: &gpb.TypedValue{
                                        Value: &gpb.TypedValue_JsonIetfVal{
                                                JsonIetfVal: []byte(strconv.FormatUint(uint64(9122), 10)),
                                        },
                                },
                        },
                },
        }

        ctx := context.Background()
        newGNMIClient := func() gpb.GNMIClient {
                gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
                if err != nil {
                        t.Fatalf("Unable to get gNMI client (%v)", err)
                }
                return gnmiClient
        }
        clients := map[string]gpb.GNMIClient{
                "c1": newGNMIClient(),
                "c2": newGNMIClient(),
        }

        eg, ctx := errgroup.WithContext(context.Background())
        eg.Go(func() error {
                _, err := clients["c1"].Set(ctx, setRequest1)
                return err
        })
        eg.Go(func() error {
                _, err := clients["c2"].Set(ctx, setRequest2)
                return err
        })
        if err := eg.Wait(); err != nil {
                t.Fatalf("Error while calling Multiple Set API %v", err)
        }
}

/**********************************************************
* gNMI GET operations
**********************************************************/
// Sample test that performs gNMI GET using subscribe once on state paths.
func TestGNMIGetPaths(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("75e16f69-06ce-4e9a-bdbb-af50339ca8c4").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // The Get() APIs in this test would panic if the switch does not return
        // state value for the Openconfig path, resulting in a test failure.
        // The test validates that the switch returns state values for the
        // specified interface Openconfig path.

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        // Fetch port MTU.
        mtu := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().State())
        t.Logf("MTU is %v", mtu)

        // Fetch /interfaces/interface[name=<port>]/state subtree.
        p := gnmi.Get(t, dut, gnmi.OC().Interface(intf).State())
        // All paths might not be present in the response. Therefore, validate members
        // of GoStruct before accessing them.
        if p.AdminStatus != oc.Interface_AdminStatus_UNSET {
                t.Logf("admin-status: %v", p.AdminStatus)
        }
        if p.Enabled != nil {
                t.Logf("enabled: %v", *p.Enabled)
        }
        if p.Mtu != nil {
                t.Logf("mtu: %v", *p.Mtu)
        }
        if p.Id != nil {
                t.Logf("ID: %v", *p.Id)
        }
        if p.HoldTime != nil {
                h := *p.HoldTime
                if h.Down != nil {
                        t.Logf("hold-time down: %v", *h.Down)
                }
                if h.Up != nil {
                        t.Logf("hold-time up: %v", *h.Up)
                }
        }

        // Fetch /interfaces/interface[name=<port>]/config subtree.
        res := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
        // All paths might not be present in the response. Therefore, validate members
        // of GoStruct before accessing them.
        if res.AdminStatus != oc.Interface_AdminStatus_UNSET {
                t.Logf("admin-status: %v", res.AdminStatus)
        }
        if res.Cpu != nil {
                t.Logf("IsCpu: %v", *res.Cpu)
        }
        if res.Enabled != nil {
                t.Logf("enabled: %v", *res.Enabled)
        }
        if res.Description != nil {
                t.Logf("description: %v", *res.Description)
        }
}

// Test that performs gNMI GET at module level.
func TestGNMIGetModulePaths(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("66ae2d27-d50e-4012-8be7-5536eb43fae8").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
        // Create getRequest message to fetch all components.
        getRequest := &gpb.GetRequest{
                Prefix: prefix,
                Path: []*gpb.Path{{
                        Elem: []*gpb.PathElem{{
                                Name: "components",
                        }, {
                                Name: "component",
                        }},
                }},
                Encoding: gpb.Encoding_PROTO,
        }

        // Fetch raw gNMI client and call Get API to send Get Request.
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
                t.Fatal("Get response is nil")
        }

        notifs := getResp.GetNotification()
        if len(notifs) != 1 {
                t.Fatalf("got %d notifications, want 1", len(notifs))
        }
        updates := notifs[0].GetUpdate()
        if len(updates) == 0 {
                t.Fatalf("got %d updates in the notification, want >=1", len(updates))
        }
        for i := range updates {
                update := updates[i].GetPath()
                // Go through all the paths to make sure they are working fine.
                if _, err := ygot.PathToString(update); err != nil {
                        t.Fatalf("Failed to convert path to string (%v) %v", err, prototext.Format(update))
                }
        }
}

// Test that performs gNMI GET at root level.
func TestGNMIGetRootPath(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("dcc2805e-8dda-4899-99ad-3f5a42f1985b").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
        // Create getRequest message to fetch root.
        getRequest := &gpb.GetRequest{
                Prefix:   prefix,
                Encoding: gpb.Encoding_PROTO,
        }

        // Fetch raw gNMI client and call Get API to send Get Request.
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
                t.Fatal("Get response is nil")
        }

        notifs := getResp.GetNotification()
        if len(notifs) < 6 {
                t.Fatalf("got %d notifications, want >= 6", len(notifs))
        }
        for updates := range notifs {
                updates := notifs[updates].GetUpdate()
                if len(updates) < 1 {
                        continue
                }
                for i := range updates {
                        update := updates[i].GetPath()
                        // Go through all the paths to make sure they are working fine.
                        if _, err := ygot.PathToString(update); err != nil {
                                t.Fatalf("Failed to convert path to string (%v) %v", err, prototext.Format(update))
                        }
                }
        }
}

func TestGnmiProtoEncodingGet(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("0c25a72c-9b1a-4f80-90eb-177924f02802").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        // Create getRequest message with ASCII encoding.
        getRequest := &gpb.GetRequest{
                Prefix: prefix,
                Path: []*gpb.Path{{
                        Elem: []*gpb.PathElem{{
                                Name: "interfaces",
                        }, {
                                Name: "interface",
                                Key:  map[string]string{"name": intf},
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

        notifs := getResp.GetNotification()
        if len(notifs) != 1 {
                t.Fatalf("got %d notifications, want 1", len(notifs))
        }
        updates := notifs[0].GetUpdate()
        if len(updates) < 1 {
                t.Fatalf("got %d updates in the notification, want >1", len(updates))
        }
        for i := range updates {
                update := updates[i].GetPath()
                // Go through all the paths to make sure they are working fine.
                pathStr, err := ygot.PathToString(update)
                t.Logf("pathStr: %v", pathStr)
                if err != nil {
                        t.Fatalf("Failed to convert path to string (%v) %v", err, update)
                }
        }

}

func TestGnmiInvalidKeyGet(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("ca3d9356-ca81-482b-aa36-8be5ac9180ba").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        // Create getRequest message with ASCII encoding.
        getRequest := &gpb.GetRequest{
                Prefix: prefix,
                Path: []*gpb.Path{{
                        Elem: []*gpb.PathElem{{
                                Name: "interfaces",
                        }, {
                                Name: "interface",
                                Key:  map[string]string{"name": "EthernetY"},
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
        if _, err := gnmiClient.Get(ctx, getRequest); err == nil {
                t.Fatalf("Set request is expected to fail but it didn't")
        }
}

func TestGnmiInvalidPathGet(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("8f834ec5-da76-4884-9d84-58fc687c4f8c").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        // Create getRequest message with ASCII encoding.
        getRequest := &gpb.GetRequest{
                Prefix: prefix,
                Path: []*gpb.Path{{
                        Elem: []*gpb.PathElem{{
                                Name: "xyz",
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
        if _, err := gnmiClient.Get(ctx, getRequest); err == nil {
                t.Fatalf("Set request is expected to fail but it didn't")
        }
}

func TestGnmiAsciiEncodingGet(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("104a2dbf-fb8d-40af-a592-99e2bfd868d2").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        // Add Prefix information for the GetRequest.
        prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}

        // Select a random front panel interface EthernetX.
        intf, err := testhelper.RandomInterface(t, dut, nil)
        if err != nil {
                t.Fatalf("Failed to fetch random interface: %v", err)
        }

        // Create getRequest message with ASCII encoding.
        getRequest := &gpb.GetRequest{
                Prefix: prefix,
                Path: []*gpb.Path{{
                        Elem: []*gpb.PathElem{{
                                Name: "interfaces",
                        }, {
                                Name: "interface",
                                Key:  map[string]string{"name": intf},
                        }},
                }},
                Type:     gpb.GetRequest_ALL,
                Encoding: gpb.Encoding_ASCII,
        }
        t.Logf("GetRequest:\n%v", getRequest)

        // Fetch get client using the raw gNMI client.
        ctx := context.Background()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        if _, err = gnmiClient.Get(ctx, getRequest); err == nil {
                t.Fatalf("Set request is expected to fail but it didn't")
        }
}

// Test that performs gNMI SET Replace at root level.
// This test will fail till the binding issue for root path is fixed (b/200096572)
func TestGNMISetReplaceRootPath(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("09df0cd9-3e23-4f8c-8a0b-9105de3a83af").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        if err := testhelper.ConfigPush(t, dut, nil); err != nil {
                t.Fatalf("Failed to push config: %v", err)
        }

        // Select a random front panel interface EthernetX.
        var intf string

        info, err := testhelper.FetchPortsOperStatus(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch port operation status: %v", err)
        }

        if len(info.Up) == 0 {
                t.Fatalf("Failed to fetch port with operation status UP: %v", err)
        }

        for _, port := range info.Up {
                if isParent, err := testhelper.IsParentPort(t, dut, port); err == nil && isParent {
                        intf = port
                        break
                }
        }

        // Get fields from interface subtree.
        if intf != "" {
                intfIDAfterSet := gnmi.Get(t, dut, gnmi.OC().Interface(intf).State()).GetId()
                t.Logf("ID After Set is %v for interface %v", intfIDAfterSet, intf)
        } else {
                t.Fatalf("Failed to fetch valid parent interface.")
        }
}

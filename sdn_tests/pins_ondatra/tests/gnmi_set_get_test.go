package gnmi_set_get_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/testt"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"google.golang.org/grpc"

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

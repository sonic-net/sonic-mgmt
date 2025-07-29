package gnoi_factory_Reset_test

// This suite of tests is to end-to-end test the gNOI File service. These tests are PINs specific
// and depend on the files that are permitted to be modiified.

import (
	"context"
	"fmt"
	"testing"

	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	//"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"

	frpb "github.com/openconfig/gnoi/factory_reset"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func TestGnoiFactoryResetSucceds(t *testing.T) {
	dut := ondatra.DUT(t, "DUT")
	t.Logf("DUT name: %v", dut.Name())

	req := &frpb.StartRequest{}
	resp, err := dut.RawAPIs().GNOI(t).FactoryReset().Start(context.Background(), req)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	_, ok := resp.GetResponse().(*frpb.StartResponse_ResetSuccess)
	if !ok {
		t.Fatalf("Expected ResetSuccess but got %v", resp.Response)
	}
	if ok {
		fmt.Sprintf("ResetSuccess: [%v]", resp.Response)
	}
}

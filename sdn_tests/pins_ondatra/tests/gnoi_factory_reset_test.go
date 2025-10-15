package gnoi_factory_reset_test

// This suite of tests is to end-to-end test the gNOI Factory Reset service. These tests are PINs specific

import (
	"context"
	"testing"

	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"

	frpb "github.com/openconfig/gnoi/factory_reset"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func TestGnoiFactoryResetReturnsResetError(t *testing.T) {

	dut := ondatra.DUT(t, "DUT")
	t.Logf("DUT name: %v", dut.Name())

	req := &frpb.StartRequest{}
	resp, err := dut.RawAPIs().GNOI(t).FactoryReset().Start(context.Background(), req)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if _, ok := resp.GetResponse().(*frpb.StartResponse_ResetError); !ok {
		t.Fatalf("Expected ResetError but got %#v", resp.Response)
	}
}

func TestGnoiFactoryResetZeroFill(t *testing.T) {

        dut := ondatra.DUT(t, "DUT")
        t.Logf("DUT name: %v", dut.Name())

        req := &frpb.StartRequest{FactoryOs: true, ZeroFill: true }
        resp, err := dut.RawAPIs().GNOI(t).FactoryReset().Start(context.Background(), req)
        if err != nil {
                t.Errorf("Unexpected error %v", err)
        }
        if _, ok := resp.GetResponse().(*frpb.StartResponse_ResetError); !ok {
                t.Fatalf("Expected ResetError but got %#v", resp.Response)
        }
}

func TestGnoiFactoryResetRetainCerts(t *testing.T) {

        dut := ondatra.DUT(t, "DUT")
        t.Logf("DUT name: %v", dut.Name())

        req := &frpb.StartRequest{FactoryOs: true, RetainCerts: true }
        resp, err := dut.RawAPIs().GNOI(t).FactoryReset().Start(context.Background(), req)
        if err != nil {
                t.Errorf("Unexpected error %v", err)
        }
        if _, ok := resp.GetResponse().(*frpb.StartResponse_ResetError); !ok {
                t.Fatalf("Expected ResetError but got %#v", resp.Response)
        }
}

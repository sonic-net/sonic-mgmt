package gnmi_wildcard_subscription_test

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"github.com/pkg/errors"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	intfPrefix   = "Ethernet"
	intfKey      = "name"
	componentKey = "name"
	queueKey     = "name"
	intfIDKey    = "interface-id"

	shortWait = 5 * time.Second
	longWait  = 20 * time.Second
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

// Test for gNMI Subscribe for Wildcard OnChange subscriptions.
func TestWCOnChangeAdminStatus(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("0cd4c21e-0af8-41d6-b637-07b6b90ba23d").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every interface through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]int)
	var portList []string
	ports := gnmi.GetAll(t, dut, gnmi.OC().InterfaceAny().Name().State())
	for _, port := range ports {
		if strings.Contains(port, intfPrefix) {
			wantUpdates[port]++
			portList = append(portList, port)
		}
	}

	intf, err := testhelper.RandomInterface(t, dut, &testhelper.RandomInterfaceParams{PortList: portList})
	if err != nil {
		t.Fatal("No enabled interface found")
	}

	state := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Enabled().State())
	predicate := oc.Interface_AdminStatus_UP
	if state {
		predicate = oc.Interface_AdminStatus_DOWN
	}

	// Open a parallel client to watch changes to the oper-status.
	// The async call needs to see the initial value be changed to
	// its updated value. If this doesn't happen in a reasonable
	// time (20 seconds) the test is failed.
	finalValueCall := gnmi.WatchAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		AdminStatus().State(), longWait, func(val *ygnmi.Value[oc.E_Interface_AdminStatus]) bool {
		port, err := fetchPathKey(val.Path, intfKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
		}
		status, present := val.Val()
		return port == intf && present && status == predicate
	})

	// Collect interfaces through subscription to be compared to the previous GET.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		AdminStatus().State(), shortWait).
		Await(t)

	gotUpdates := make(map[string]int)
	for _, val := range initialValues {
		port, err := fetchPathKey(val.Path, intfKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if val.IsPresent() && strings.Contains(port, intfPrefix) {
			gotUpdates[port]++
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got): %v", diff)
	}

	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Enabled().Config(), !state)
	defer gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Enabled().Config(), state)

	_, foundUpdate := finalValueCall.Await(t)
	if !foundUpdate {
		t.Errorf("Interface did not receive an update for %v enabled %v", intf, !state)
	}
}

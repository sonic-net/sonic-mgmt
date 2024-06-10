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

func TestWCOnChangeOperStatus(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("d0a07207-b6a2-4045-8f16-243b8ad693b6").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every interface through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]bool)
	ports := gnmi.GetAll(t, dut, gnmi.OC().InterfaceAny().Name().State())
	for _, port := range ports {
		if strings.Contains(port, intfPrefix) {
			wantUpdates[port] = true
		}
	}

	intf, err := testhelper.RandomInterface(t, dut, &testhelper.RandomInterfaceParams{})
	if err != nil {
		t.Fatal("No enabled interface found")
	}

	// Open a parallel client to watch changes to the oper-status.
	// The async call needs to see the initial value be changed to
	// its updated value. If this doesn't happen in a reasonable
	// time (20 seconds) the test is failed.
	finalValueCall := gnmi.WatchAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		OperStatus().State(), longWait, func(val *ygnmi.Value[oc.E_Interface_OperStatus]) bool {
		port, err := fetchPathKey(val.Path, intfKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
		}
		state, present := val.Val()
		return port == intf && present && state == oc.Interface_OperStatus_DOWN
	})

	// Collect Interfaces through Subscription to be compared to the previous GET.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		OperStatus().State(), shortWait).
		Await(t)

	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Enabled().Config(), false)
	defer gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Enabled().Config(), true)

	gotUpdates := make(map[string]bool)
	for _, val := range initialValues {
		port, err := fetchPathKey(val.Path, intfKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if val.IsPresent() && strings.Contains(port, intfPrefix) {
			gotUpdates[port] = true
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got): %v", diff)
	}

	_, foundUpdate := finalValueCall.Await(t)
	if !foundUpdate {
		t.Errorf("Interface did not receive an update to %s", intf)
	}
}

func TestWCOnChangePortSpeed(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("59669bd7-e2e2-4734-869a-4bf4110b4cdc").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every interface through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]int)
	paths := gnmi.CollectAll(t, dut, gnmi.OC().InterfaceAny().Ethernet().
		PortSpeed().State(), shortWait).
		Await(t)
	for _, path := range paths {
		port, isfp, err := extractFrontPanelPortName(path.Path)
		if err != nil {
			t.Errorf("extractFrontPanelPortName(%v) failed: %v", path.Path, err)
			continue
		}
		if !isfp {
			continue
		}
		if strings.Contains(port, intfPrefix) {
			wantUpdates[port]++
		}
	}

	var intf string
	var speed oc.E_IfEthernet_ETHERNET_SPEED
	newSpeed := oc.IfEthernet_ETHERNET_SPEED_UNSET

	// Find an interface with an alternate speed
	for port := range wantUpdates {
		if empty, err := testhelper.TransceiverEmpty(t, dut, port); err != nil || empty {
			continue
		}
		speed = gnmi.Get(t, dut, gnmi.OC().Interface(port).Ethernet().PortSpeed().State())
		speeds, err := testhelper.SupportedSpeedsForPort(t, dut, port)
		if err != nil {
			t.Logf("SupportedSpeedsForPort(%v) failed: %v", port, err)
			continue
		}
		if len(speeds) > 1 {
			intf = port
			for _, s := range speeds {
				if s != speed {
					newSpeed = s
					break
				}
			}
			break
		}
	}
	if newSpeed == oc.IfEthernet_ETHERNET_SPEED_UNSET {
		t.Fatal("No alternate speeds found")
	}

	// Open a parallel client to watch changes to the oper-status.
	// The async call needs to see the initial value be changed to
	// its updated value. If this doesn't happen in a reasonable
	// time (20 seconds) the test is failed.
	finalValueCall := gnmi.WatchAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		Ethernet().
		PortSpeed().State(), longWait, func(val *ygnmi.Value[oc.E_IfEthernet_ETHERNET_SPEED]) bool {
		port, err := fetchPathKey(val.Path, intfKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
		}
		if speed, present := val.Val(); port == intf && present && speed == newSpeed {
			return true
		}
		return false
	})

	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		Ethernet().
		PortSpeed().State(), shortWait).
		Await(t)

	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Ethernet().PortSpeed().Config(), newSpeed)
	defer gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Ethernet().PortSpeed().Config(), speed)

	gotUpdates := make(map[string]int)
	for _, val := range initialValues {
		port, err := fetchPathKey(val.Path, "name")
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if val.IsPresent() {
			if _, ok := wantUpdates[port]; !ok {
				t.Errorf("Port not found in On Change update: %v", port)
			}
			gotUpdates[port]++
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got): %v", diff)
	}

	_, foundUpdate := finalValueCall.Await(t)
	if !foundUpdate {
		t.Errorf("Interface did not receive an update for %v %v to %v", intf, speed, newSpeed)
	}
}

func fetchPathKey(path *gpb.Path, id string) (string, error) {
	if path == nil {
		return "", errors.New("received nil path")
	}
	pathStr, err := ygot.PathToString(path)
	if err != nil {
		return "", errors.Errorf("ygot.PathToString() failed: %v", err)
	}
	for _, e := range path.GetElem() {
		if e.GetKey() == nil {
			continue
		}
		if key, ok := e.GetKey()[id]; ok {
			return key, nil
		}
		return "", errors.Errorf("failed to get key from path: %v", pathStr)
	}
	return "", errors.Errorf("failed to find key for path: %v", pathStr)
}

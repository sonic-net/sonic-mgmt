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

func TestWCOnChangeId(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("f7e8ab6b-4d10-4986-811c-63044295a74d").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every interface through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]bool)
	var portList []string
	paths := gnmi.CollectAll(t, dut, gnmi.OC().InterfaceAny().Id().State(), 5*time.Second).Await(t)
	for _, path := range paths {
		port, isfp, err := extractFrontPanelPortName(path.Path)
		if err != nil || !isfp {
			continue
		}
		if strings.Contains(string(port), intfPrefix) {
			wantUpdates[port] = true
			portList = append(portList, port)
		}
	}

	// Randomly select one intf
	intf, err := testhelper.RandomInterface(t, dut, &testhelper.RandomInterfaceParams{PortList: portList, OperDownOk: true})
	if err != nil {
		t.Fatal("No interface found")
	}

	res := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Config())
	idPath := gnmi.OC().Interface(intf).Id()

	var originalID uint32 = 0
	var modifiedID uint32
	var idExist bool = false
	gotUpdates := make(map[string]uint32)

	if res.Id != nil {
		// If the interface has already an ID set, save it so it can be restored.
		originalID = *res.Id
		idExist = true
	} else {
		rand.Seed(time.Now().Unix())
		originalID = uint32(rand.Intn(100))
	}

	modifiedID = uint32(originalID + 800)

	var wg sync.WaitGroup
	wg.Add(1)

	go func(intf string) {
		defer wg.Done()
		// This goroutine runs ON_CHANGE subscription, wait change of id
		// We are checking only on interface, so we just need the one got checked
		value := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
			InterfaceAny().
			Id().State(), 30*time.Second).Await(t)

		for _, v := range value {
			// Extract front panel port.
			fp, isfp, err := extractFrontPanelPortName(v.Path)
			if err != nil {
				t.Errorf("extractFrontPanelPortName() failed: %v", err)
				continue
			}
			if !isfp {
				continue
			}

			if upd, present := v.Val(); present {
				if intf == fp {
					if wantUpdates[fp] {
						gotUpdates[fp] = upd
					}
				}
			}
		}
	}(intf)

	// Replace the originalID value with modifiedID if originalID exists before the test.
	if idExist {
		gnmi.Delete(t, dut, idPath.Config())
		gnmi.Update(t, dut, idPath.Config(), modifiedID)
	} else {
		gnmi.Update(t, dut, idPath.Config(), modifiedID)
	}
	time.Sleep(30 * time.Second)
	wg.Wait()

	// When originalID does exist, sets the originalID back at the end of the test
	defer func() {
		if idExist {
			gnmi.Delete(t, dut, idPath.Config())
			gnmi.Update(t, dut, idPath.Config(), originalID)
			afterCall := gnmi.Watch(t, dut, gnmi.OC().Interface(intf).Id().State(), longWait, func(val *ygnmi.Value[uint32]) bool {
				v, ok := val.Val()
				return ok && v == originalID
			})
			valueAfterCall, _ := afterCall.Await(t)
			t.Logf("Modified ID got replaced back to originalID %v", valueAfterCall)
		} else {
			gnmi.Delete(t, dut, idPath.Config())
		}
	}()

	if wantUpdates[intf] {
		if modifiedID != gotUpdates[intf] {
			t.Errorf("ID is updated for %v. Want to get %v, got %v ", intf, modifiedID, gotUpdates[intf])
		}
	}
}

// Returns the port name, whether its front-panel or not, and an error
func extractFrontPanelPortName(path *gpb.Path) (string, bool, error) {
	if path == nil {
		return "", false, errors.New("received nil path")
	}

	pathStr, err := ygot.PathToString(path)
	if err != nil {
		return "", false, errors.Errorf("ygot.PathToString() failed: %v", err)
	}

	if len(path.GetElem()) < 3 {
		return "", false, errors.Errorf("No valid front panel name from path: %v", pathStr)
	}

	fpEle := path.GetElem()[1]
	if fpEle == nil {
		return "", false, errors.Errorf("failed to get key from path: %v", pathStr)
	}

	fpKey, ok := fpEle.GetKey()["name"]
	if !ok {
		return "", false, errors.Errorf("failed to get key from path: %v", pathStr)
	}

	if !strings.Contains(fpKey, "Ethernet") {
		return "", false, nil
	}

	return fpKey, true, nil
}

func TestWCOnChangeEthernetMacAddress(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("c83a6e46-95a4-4dc7-a934-48c92fa0f136").Teardown(t)
	t.Skip()
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

	intf, err := testhelper.RandomInterface(t, dut, &testhelper.RandomInterfaceParams{PortList: portList, OperDownOk: true})
	if err != nil {
		t.Fatal("No interface found")
	}

	origMAC := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Ethernet().MacAddress().State())
	newMAC := "00:11:22:33:44:55"
	if origMAC == newMAC {
		newMAC = "55:44:33:22:11:00"
	}

	// Open a parallel client to watch changes to the `mac-address`.
	// The async call needs to see the initial value be changed to
	// its updated value. If this doesn't happen in a reasonable
	// time (20 seconds) the test is failed.
	finalValueCall := gnmi.WatchAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		Ethernet().
		MacAddress().State(), longWait, func(val *ygnmi.Value[string]) bool {
		port, err := fetchPathKey(val.Path, intfKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
		}
		mac, present := val.Val()
		return port == intf && present && mac == newMAC
	})

	// Collect interfaces through subscription to be compared to the previous GET.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		Ethernet().
		MacAddress().State(), shortWait).
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

	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Ethernet().MacAddress().Config(), newMAC)
	defer gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Ethernet().MacAddress().Config(), origMAC)

	_, foundUpdate := finalValueCall.Await(t)
	if !foundUpdate {
		t.Errorf("Interface did not receive an update for %v `id` %s", intf, newMAC)
	}
}

func TestWCOnChangeIntegratedCircuitNodeId(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("7dd451b1-4d2b-4c79-90f5-1d419bdecc67").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every integrated circuit component through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]int)
	var icList []string
	components := gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().Name().State())
	for _, component := range components {
		if component == "" {
			continue
		}
		compTypeVal, present := testhelper.LookupComponentTypeOCCompliant(t, dut, component)
		if !present || compTypeVal != "INTEGRATED_CIRCUIT" {
			continue
		}
		wantUpdates[component]++
		icList = append(icList, component)
	}
	if len(icList) == 0 {
		t.Fatal("No integrated circuit components found")
	}

	ic := icList[len(icList)-1]

	origNodeID := gnmi.Get(t, dut, gnmi.OC().Component(ic).IntegratedCircuit().NodeId().State())
	newNodeID := origNodeID + 1

	// Open a parallel client to watch changes to the `node-id`.
	// The async call needs to see the initial value be changed to
	// its updated value. If this doesn't happen in a reasonable
	// time (20 seconds) the test is failed.
	finalValueCall := gnmi.WatchAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		ComponentAny().
		IntegratedCircuit().
		NodeId().State(), longWait, func(val *ygnmi.Value[uint64]) bool {
		component, err := fetchPathKey(val.Path, componentKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
		}
		id, present := val.Val()
		return component == ic && present && id == newNodeID
	})

	// Collect interfaces through subscription to be compared to the previous GET.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		ComponentAny().
		IntegratedCircuit().
		NodeId().State(), shortWait).
		Await(t)

	gotUpdates := make(map[string]int)
	for _, val := range initialValues {
		component, err := fetchPathKey(val.Path, componentKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if val.IsPresent() {
			gotUpdates[component]++
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got): %v", diff)
	}

	gnmi.Replace(t, dut, gnmi.OC().Component(ic).IntegratedCircuit().NodeId().Config(), newNodeID)
	defer gnmi.Replace(t, dut, gnmi.OC().Component(ic).IntegratedCircuit().NodeId().Config(), origNodeID)

	_, foundUpdate := finalValueCall.Await(t)
	if !foundUpdate {
		t.Errorf("Interface did not receive an update for %v `id` %v", ic, newNodeID)
	}
}

func TestWCOnChangeComponentOperStatus(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("794672b0-e15f-4a72-8619-f5a0bbb45e9b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every component with an oper-status through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]int)
	vals := gnmi.LookupAll(t, dut, gnmi.OC().ComponentAny().OperStatus().State())
	for _, val := range vals {
		if !val.IsPresent() {
			continue
		}
		component, err := fetchPathKey(val.Path, componentKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		wantUpdates[component]++
	}

	// Collect components through Subscription to be compared to the previous GET.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		ComponentAny().
		OperStatus().State(), shortWait).
		Await(t)

	gotUpdates := make(map[string]int)
	for _, val := range initialValues {
		component, err := fetchPathKey(val.Path, intfKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if val.IsPresent() {
			gotUpdates[component]++
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got):\n%v", diff)
	}
}

type counterSubscription struct {
	dut *ondatra.DUTDevice
	t   *testing.T
}

func (c counterSubscription) subToInUnicastPkts() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		InUnicastPkts().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToInBroadcastPkts() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		InBroadcastPkts().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToInMulticastPkts() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		InMulticastPkts().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToOutUnicastPkts() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		OutUnicastPkts().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToOutBroadcastPkts() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		OutBroadcastPkts().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToOutMulticastPkts() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		OutMulticastPkts().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToInOctets() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		InOctets().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToOutOctets() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		OutOctets().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToInDiscards() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		InDiscards().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToOutDiscards() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		OutDiscards().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToInErrors() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		InErrors().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToOutErrors() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		OutErrors().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToInFcsErrors() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		InterfaceAny().
		Counters().
		InFcsErrors().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToTransmitPkts() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		Qos().
		InterfaceAny().
		Output().
		QueueAny().
		TransmitPkts().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToTransmitOctets() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		Qos().
		InterfaceAny().
		Output().
		QueueAny().
		TransmitOctets().State(), longWait).
		Await(c.t)
}

func (c counterSubscription) subToDroppedPkts() []*ygnmi.Value[uint64] {
	return gnmi.CollectAll(c.t, gnmiOpts(c.t, c.dut, gpb.SubscriptionMode_TARGET_DEFINED), gnmi.OC().
		Qos().
		InterfaceAny().
		Output().
		QueueAny().
		DroppedPkts().State(), longWait).
		Await(c.t)
}

type counterTest struct {
	uuid   string
	subfun func() []*ygnmi.Value[uint64]
}

func TestWcTargetDefinedCounters(t *testing.T) {
	dut := ondatra.DUT(t, "DUT")
	testCases := []struct {
		name     string
		function func(*testing.T)
	}{
		{
			name: "InUnicastPkts",
			function: counterTest{
				uuid: "488f9daa-9b8d-455f-b580-5dd5491d64b5",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToInUnicastPkts,
			}.targetDefinedCounterTest,
		},
		{
			name: "InBroadcastPkts",
			function: counterTest{
				uuid: "edffb8d9-9040-4188-b9d3-bdb083a61f27",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToInBroadcastPkts,
			}.targetDefinedCounterTest,
		},
		{
			name: "InMulticastPkts",
			function: counterTest{
				uuid: "1b20f216-1bb5-4ed6-b2ed-5a09942a2eee",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToInMulticastPkts,
			}.targetDefinedCounterTest,
		},
		{
			name: "OutUnicastPkts",
			function: counterTest{
				uuid: "712042e8-b057-4f0c-bd0b-cde2861a3555",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToOutUnicastPkts,
			}.targetDefinedCounterTest,
		},
		{
			name: "OutBroadcastPkts",
			function: counterTest{
				uuid: "06cf226d-36ad-4dec-958e-89a6c2d42506",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToOutBroadcastPkts,
			}.targetDefinedCounterTest,
		},
		{
			name: "OutMulticastPkts",
			function: counterTest{
				uuid: "4b81e22d-5dd2-4ea2-95bd-25d3655978a3",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToOutMulticastPkts,
			}.targetDefinedCounterTest,
		},
		{
			name: "InOctets",
			function: counterTest{
				uuid: "30e25f1b-f79c-4824-adac-4fa6feba2f02",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToInOctets,
			}.targetDefinedCounterTest,
		},
		{
			name: "OutOctets",
			function: counterTest{
				uuid: "9a55189e-c1a4-42c9-a02d-eec3d8ec5d1b",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToOutOctets,
			}.targetDefinedCounterTest,
		},
		{
			name: "InDiscards",
			function: counterTest{
				uuid: "744c4e37-e6d2-400f-999b-adb6a81b461d",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToInDiscards,
			}.targetDefinedCounterTest,
		},
		{
			name: "OutDiscards",
			function: counterTest{
				uuid: "69075f31-d825-4eb2-9bbe-e9bfb95b36a6",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToOutDiscards,
			}.targetDefinedCounterTest,
		},
		{
			name: "InErrors",
			function: counterTest{
				uuid: "b416b679-f336-4d3c-9e70-cc907508cda1",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToInErrors,
			}.targetDefinedCounterTest,
		},
		{
			name: "OutErrors",
			function: counterTest{
				uuid: "76b515f6-9464-42ee-aa31-2210c5c9fc29",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToOutErrors,
			}.targetDefinedCounterTest,
		},
		{
			name: "InFcsErrors",
			function: counterTest{
				uuid: "6e6aac39-eaa4-4d10-890b-aec13e981733",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToInFcsErrors,
			}.targetDefinedCounterTest,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, testCase.function)
	}
}

func TestWcTargetDefinedQosCountersWc(t *testing.T) {
	dut := ondatra.DUT(t, "DUT")

	testCases := []struct {
		name     string
		function func(*testing.T)
	}{
		{
			name: "TransmitPkts",
			function: counterTest{
				uuid: "7b1133b0-b934-4948-b087-d63108418dcb",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToTransmitPkts,
			}.targetDefinedQosCounterWcTest,
		},
		{
			name: "TransmitOctets",
			function: counterTest{
				uuid: "9c36c0ca-2551-4a7d-a7de-d47fef53d158",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToTransmitOctets,
			}.targetDefinedQosCounterWcTest,
		},
		{
			name: "DroppedPkts",
			function: counterTest{
				uuid: "88985776-2b1e-4afc-8e7b-dd1114f7070c",
				subfun: counterSubscription{
					dut: dut,
					t:   t,
				}.subToDroppedPkts,
			}.targetDefinedQosCounterWcTest,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, testCase.function)
	}
}

func (c counterTest) targetDefinedCounterTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every interface through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]int)
	ports := gnmi.GetAll(t, dut, gnmi.OC().InterfaceAny().Name().State())
	for _, port := range ports {
		if strings.Contains(port, intfPrefix) {
			wantUpdates[port] = 2 // initial subscription plus one timed update.
		}
	}

	// Collect interfaces through subscription to be compared to the previous GET.
	subcriptionValues := c.subfun()

	gotUpdates := make(map[string]int)
	for _, val := range subcriptionValues {
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
		t.Errorf("Update notifications comparison failed! (-want +got):\n%v", diff)
	}
}

// UMF default queue name is interface-id:queueName
// This name is used for the queue name without proper number->string mapping
func isQueueConfigured(qname, iname string) bool {
	return !strings.HasPrefix(qname, iname)
}

func (c counterTest) targetDefinedQosCounterWcTest(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every interface through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]uint64)
	qosInterfaces := gnmi.Get(t, dut, gnmi.OC().Qos().State()).Interface
	for intf := range qosInterfaces {
		queueNames := gnmi.GetAll(t, dut, gnmi.OC().Qos().Interface(intf).Output().QueueAny().Name().State())
		for _, queueName := range queueNames {
			if !isQueueConfigured(queueName, intf) {
				continue
			}
			wantUpdates[intf+","+queueName] = 2 // initial subscription plus one timed update.
		}
	}

	// Collect interfaces through subscription to be compared to the previous GET.
	subcriptionValues := c.subfun()

	gotUpdates := make(map[string]uint64)
	for _, val := range subcriptionValues {
		intfQueue, err := fetchQosKey(val.Path)
		if err != nil {
			if !strings.Contains(err.Error(), "unconfigured") {
				t.Logf("fetchQosKey() failed: %v", err)
			}
			continue
		}

		interfaceID, queueName := intfQueue[0], intfQueue[1]
		if val.IsPresent() {
			gotUpdates[interfaceID+","+queueName]++
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got):\n%v", diff)
	}
}

func fetchQosKey(path *gpb.Path) ([]string, error) {
	if path == nil {
		return nil, errors.New("received nil path")
	}
	pathStr, err := ygot.PathToString(path)
	if err != nil {
		return nil, errors.Errorf("ygot.PathToString() failed: %v", err)
	}

	if len(path.GetElem()) != 8 {
		return nil, errors.Errorf("no valid interface id or queue name from path: %v", pathStr)
	}

	interfaceEle := path.GetElem()[2].GetKey()
	if interfaceEle == nil {
		return nil, errors.Errorf("no valid interface id from path: %v", pathStr)
	}
	interfaceKey, ok := interfaceEle[intfIDKey]
	if !ok {
		return nil, errors.Errorf("no valid interface id from path: %v", pathStr)
	}

	queueEle := path.GetElem()[5].GetKey()
	if queueEle == nil {
		return nil, errors.Errorf("no valid queue name from path: %v", pathStr)
	}
	queueName, ok := queueEle[queueKey]
	if !ok {
		return nil, errors.Errorf("no valid queue name from path: %v", pathStr)
	}
	if !isQueueConfigured(queueName, interfaceKey) {
		return nil, errors.Errorf("unconfigured queue found: %v", pathStr)
	}

	return []string{interfaceKey, queueName}, nil
}

func TestWCOnChangeSoftwareModuleModuleType(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("ff05e9c6-b57b-4128-9535-e8543dc5aedc").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every software module component through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]int)
	components := gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().Name().State())
	for _, component := range components {
		if component == "" {
			continue
		}
		compTypeVal, present := testhelper.LookupComponentTypeOCCompliant(t, dut, component)
		if !present || compTypeVal != "SOFTWARE_MODULE" {
			continue
		}
		wantUpdates[component]++
	}
	if len(wantUpdates) == 0 {
		t.Fatal("No software module components found")
	}

	// Collect interfaces through subscription to be compared to the previous GET.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		ComponentAny().
		SoftwareModule().
		ModuleType().State(), shortWait).
		Await(t)

	gotUpdates := make(map[string]int)
	for _, val := range initialValues {
		component, err := fetchPathKey(val.Path, componentKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if val.IsPresent() {
			gotUpdates[component]++
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got):\n%v", diff)
	}
}

func TestWCOnChangeHardwarePort(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("acfc84d1-b76f-45b3-bb8f-267abca3b2d2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Collect every interface through a GET to be compared to the SUBSCRIBE.
	wantUpdates := make(map[string]int)
	ports := gnmi.GetAll(t, dut, gnmi.OC().InterfaceAny().Name().State())
	for _, port := range ports {
		if strings.Contains(port, intfPrefix) {
			wantUpdates[port]++
		}
	}

	// Collect interfaces through subscription to be compared to the previous GET.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		InterfaceAny().
		HardwarePort().State(), shortWait).
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
}

func TestWCOnChangeComponentType(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("e07ea34c-b217-4aef-99ac-2516b0b5c393").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Determine that updates are received from all expected components.
	wantUpdates := make(map[string]int)
	components := gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().State())
	for _, component := range components {
		if component.GetName() == "" {
			continue
		}

		if _, present := testhelper.LookupComponentTypeOCCompliant(t, dut, component.GetName()); !present {
			continue
		}

		wantUpdates[component.GetName()]++
	}

	// Collect components updates from ON_CHANGE subscription.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		ComponentAny().
		Type().State(), shortWait).
		Await(t)

	gotUpdates := make(map[string]int)
	for _, val := range initialValues {
		component, err := fetchPathKey(val.Path, componentKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if val.IsPresent() {
			gotUpdates[component] = 1
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got):\n%v", diff)
	}
}

func TestWCOnChangeComponentParent(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("9c889baf-c3c2-4ce3-bb74-36b78c5b77ca").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Determine expected components.
	wantUpdates := make(map[string]string)
	components := gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().State())
	for _, component := range components {
		if component == nil || component.Name == nil || component.GetName() == "" {
			continue
		}
		if component.Parent != nil && component.GetParent() != "" {
			wantUpdates[component.GetName()] = component.GetParent()
		}
	}

	// Collect component updates from ON_CHANGE subscription.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		ComponentAny().
		Parent().State(), shortWait).
		Await(t)

	gotUpdates := make(map[string]string)
	for _, val := range initialValues {
		component, err := fetchPathKey(val.Path, componentKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if upd, present := val.Val(); present && upd != "" {
			gotUpdates[component] = upd
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got):\n%v", diff)
	}
}

func TestWCOnChangeComponentSoftwareVersion(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("25e36fae-82e7-4d51-8f60-df6fb139f6ca").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Determine expected components.
	wantUpdates := make(map[string]string)
	components := gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().State())
	for _, component := range components {
		if component == nil || component.Name == nil || component.GetName() == "" {
			continue
		}
		if component.SoftwareVersion != nil && component.GetSoftwareVersion() != "" {
			wantUpdates[component.GetName()] = component.GetSoftwareVersion()
		}
	}

	// Collect component updates from ON_CHANGE subscription.
	initialValues := gnmi.CollectAll(t, gnmiOpts(t, dut, gpb.SubscriptionMode_ON_CHANGE), gnmi.OC().
		ComponentAny().
		SoftwareVersion().State(), shortWait).
		Await(t)

	gotUpdates := make(map[string]string)
	for _, val := range initialValues {
		component, err := fetchPathKey(val.Path, componentKey)
		if err != nil {
			t.Errorf("fetchPathKey() failed: %v", err)
			continue
		}
		if upd, present := val.Val(); present && upd != "" {
			gotUpdates[component] = upd
		}
	}

	if diff := cmp.Diff(wantUpdates, gotUpdates); diff != "" {
		t.Errorf("Update notifications comparison failed! (-want +got):\n%v", diff)
	}
}

func gnmiOpts(t *testing.T, dut *ondatra.DUTDevice, mode gpb.SubscriptionMode) *gnmi.Opts {
	client, err := dut.RawAPIs().BindingDUT().DialGNMI(context.Background())
	if err != nil {
		t.Fatalf("DialGNMI() failed: %v", err)
	}
	return dut.GNMIOpts().
		WithClient(client).
		WithYGNMIOpts(ygnmi.WithSubscriptionMode(mode))
}

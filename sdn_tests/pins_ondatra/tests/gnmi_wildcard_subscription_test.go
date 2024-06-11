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

func gnmiOpts(t *testing.T, dut *ondatra.DUTDevice, mode gpb.SubscriptionMode) *gnmi.Opts {
        client, err := dut.RawAPIs().BindingDUT().DialGNMI(context.Background())
        if err != nil {
                t.Fatalf("DialGNMI() failed: %v", err)
        }
        return dut.GNMIOpts().
                WithClient(client).
                WithYGNMIOpts(ygnmi.WithSubscriptionMode(mode))
}

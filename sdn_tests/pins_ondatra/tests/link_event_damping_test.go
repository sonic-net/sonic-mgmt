package link_event_damping_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
)

const (
	holdTimeDisableMs                 = uint32(0)
	holdTimeEnableMs                  = uint32(1000)
	loopbackModeEnabled               = oc.Interfaces_LoopbackModeType_FACILITY
	waitAFterLinkEventDampingDisable  = 1 * time.Second  // Wait time after disabling damping config to ensure damped event got advertised and updated in DB.
	waitAfterLoopbackModeChange       = 10 * time.Second // Maximum time for link to flap and get updated in state DB after loopback-mode change.
	configTimeout                     = 5 * time.Second  // Maximum allowed time for a config to get programmed.
	upTransitionNotificationTimeout   = 3 * time.Second  // Maximum allowed time for test to receive link up event notification on admin enable operation.
	downTransitionNotificationTimeout = 3 * time.Second  // Maximum allowed time for test to receive link down event notification on admin disable operation.
)

func setLinkEventDampingConfig(t *testing.T, dut *ondatra.DUTDevice, intf string, holdTimeUp uint32) {
	t.Helper()
	// Configure the link event damping config.
	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).HoldTime().Up().Config(), holdTimeUp)
	gnmi.Await(t, dut, gnmi.OC().Interface(intf).HoldTime().Up().State(), configTimeout, holdTimeUp)
}

func fetchLinkEventDampingConfig(t *testing.T, dut *ondatra.DUTDevice, intf string) uint32 {
	t.Helper()
	// Lookup the hold time UP state value.
	holdTimeUp, present := gnmi.Lookup(t, dut, gnmi.OC().Interface(intf).HoldTime().Up().State()).Val()
	if present {
		return holdTimeUp
	}
	return 0
}

func setLoopbackMode(t *testing.T, dut *ondatra.DUTDevice, intf string, loopbackMode oc.E_Interfaces_LoopbackModeType) {
	t.Helper()
	// Configure the loopback-mode.
	gnmi.Replace(t, dut, gnmi.OC().Interface(intf).LoopbackMode().Config(), loopbackMode)
	gnmi.Await(t, dut.GNMIOpts().WithYGNMIOpts(ygnmi.WithSubscriptionMode(gpb.SubscriptionMode_ON_CHANGE)), gnmi.OC().Interface(intf).LoopbackMode().State(), configTimeout, loopbackMode)
}

func fetchLoopbackMode(t *testing.T, dut *ondatra.DUTDevice, intf string) oc.E_Interfaces_LoopbackModeType {
	t.Helper()
	// Lookup the loopback mode state value.
	loopbackMode, present := gnmi.Lookup(t, dut, gnmi.OC().Interface(intf).LoopbackMode().State()).Val()
	if !present {
		return oc.Interfaces_LoopbackModeType_NONE
	}
	return loopbackMode
}

func restoreConfig(t *testing.T, dut *ondatra.DUTDevice, control *ondatra.DUTDevice, intf string, controlIntf string, loopbackModeDut oc.E_Interfaces_LoopbackModeType,
	holdTimeUpDut uint32, holdTimeUpControl uint32) {
	t.Helper()

	setLoopbackMode(t, dut, intf, loopbackModeDut)
	time.Sleep(waitAfterLoopbackModeChange)

	var dutIntfNotUp bool = false
	var controlIntfNotUp bool = false
	// Verify port is UP after test.
	if operStatus := gnmi.Get(t, dut, gnmi.OC().Interface(intf).OperStatus().State()); operStatus != oc.Interface_OperStatus_UP {
		t.Errorf("DUT: got %v but want %v.", operStatus, oc.Interface_OperStatus_UP)
		dutIntfNotUp = true
	}
	if operStatus := gnmi.Get(t, control, gnmi.OC().Interface(controlIntf).OperStatus().State()); operStatus != oc.Interface_OperStatus_UP {
		t.Errorf("Control switch: got %v but want %v.", operStatus, oc.Interface_OperStatus_UP)
		controlIntfNotUp = true
	}

	// If port is not UP, try to bring it UP.
	if dutIntfNotUp || controlIntfNotUp {
		if dutIntfNotUp {
			gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Enabled().Config(), true)
		}
		if controlIntfNotUp {
			gnmi.Replace(t, control, gnmi.OC().Interface(controlIntf).Enabled().Config(), true)
		}
		maxTimeForPortToComeUp := 15 * time.Second
		if err := testhelper.WaitForInterfaceState(t, dut, intf, oc.Interface_OperStatus_UP, maxTimeForPortToComeUp); err != nil {
			t.Errorf("DUT: failed to bring port UP: %v", err)
		}
		if err := testhelper.WaitForInterfaceState(t, dut, intf, oc.Interface_OperStatus_UP, maxTimeForPortToComeUp); err != nil {
			t.Errorf("Control switch: failed to bring port UP: %v", err)
		}
	}

	setLinkEventDampingConfig(t, dut, intf, holdTimeUpDut)
	setLinkEventDampingConfig(t, control, controlIntf, holdTimeUpControl)
}

// Flaps a port N times and collects the port oper status change notifications.
func flapPortAndCollectOperStatusNotifications(t *testing.T, dut *ondatra.DUTDevice, intf string, numberOfFlaps int,
	verifyStateAfterOp bool, timeout time.Duration) ([]*ygnmi.Value[oc.E_Interface_OperStatus], error) {
	t.Helper()

	var operStatusSamples []*ygnmi.Value[oc.E_Interface_OperStatus]
	var failed bool = false

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(context.Background(), grpc.WithBlock())
		if err != nil {
			t.Fatalf("Unable to get gNMI client (%v)", err)
		}
		operStatusSamples = gnmi.Collect(t, dut.GNMIOpts().WithClient(gnmiClient).
			WithYGNMIOpts(ygnmi.WithSubscriptionMode(gpb.SubscriptionMode_ON_CHANGE)), gnmi.OC().Interface(intf).
			OperStatus().State(), timeout).Await(t)
		// One extra sample is always received during collection - sample received
		// immediately after subscription, so remove that sample from the list.
		if len(operStatusSamples) >= 1 {
			operStatusSamples = operStatusSamples[1:]
		}
		t.Logf("Successfully got ON_CHANGE oper status sample: %v", operStatusSamples)
	}()

	// Wait for ON_CHANGE collect request to be sent before flapping the port.
	time.Sleep(2 * time.Second)
	for i := 0; i < numberOfFlaps; i++ {
		t.Logf("Flap count: %v", i+1)
		gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Enabled().Config(), false)
		if verifyStateAfterOp {
			if err := testhelper.WaitForInterfaceState(t, dut, intf, oc.Interface_OperStatus_DOWN, downTransitionNotificationTimeout); err != nil {
				t.Errorf("%v", err)
				failed = true
			}
		} else {
			time.Sleep(downTransitionNotificationTimeout)
		}
		gnmi.Replace(t, dut, gnmi.OC().Interface(intf).Enabled().Config(), true)
		if verifyStateAfterOp {
			if err := testhelper.WaitForInterfaceState(t, dut, intf, oc.Interface_OperStatus_UP, upTransitionNotificationTimeout); err != nil {
				t.Errorf("%v", err)
				failed = true
			}
		} else {
			time.Sleep(upTransitionNotificationTimeout)
		}
	}

	// Wait for oper status sample collection go routine to complete before
	// verifying the sample result.
	wg.Wait()

	if failed == true {
		return nil, errors.Errorf("Verify state failed after port operation.")
	}
	return operStatusSamples, nil
}

func isLinkUp(t *testing.T, dut *ondatra.DUTDevice, control *ondatra.DUTDevice, intf string, controlIntf string) error {
	t.Helper()

	// Check port is UP.
	if operStatus := gnmi.Get(t, dut, gnmi.OC().Interface(intf).OperStatus().State()); operStatus != oc.Interface_OperStatus_UP {
		return errors.Errorf("DUT: got %v oper status but want %v.", operStatus, oc.Interface_OperStatus_UP)
	}
	if operStatus := gnmi.Get(t, control, gnmi.OC().Interface(controlIntf).OperStatus().State()); operStatus != oc.Interface_OperStatus_UP {
		return errors.Errorf("control switch: got %v oper status but want %v.", operStatus, oc.Interface_OperStatus_UP)
	}
	return nil
}

// Returns a port to run the test.
func selectPortToRunTest(t *testing.T, dut *ondatra.DUTDevice, control *ondatra.DUTDevice) (string, string, error) {
	t.Helper()

	var portList []string
	for _, port := range dut.Ports() {
		portList = append(portList, port.Name())
	}

	dutIntf, err := testhelper.RandomInterface(t, dut, &testhelper.RandomInterfaceParams{PortList: portList})
	if err != nil {
		return "", "", errors.Errorf("RandomInterface failed to get an UP interface on DUT: %v", err)
	}
	for _, port := range dut.Ports() {
		if port.Name() == dutIntf {
			if control.Port(t, port.ID()) == nil {
				return "", "", errors.Errorf("control interface for DUT interface %v not found", dutIntf)
			}
			return dutIntf, control.Port(t, port.ID()).Name(), nil
		}
	}
	return "", "", errors.Errorf("control interface for DUT interface %v not found", dutIntf)
}

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

// Disables the link event damping config on a link and does N flaps on the
// interface and verifies that link events are not damped.
func TestLinkEventDampingConfigDisabled(t *testing.T) {
	// Report results to TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("396d27cb-f951-4acf-8cec-98b17a9a5175").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	control := ondatra.DUT(t, "CONTROL")
	// Select a random UP interface.
	intf, controlIntf, err := selectPortToRunTest(t, dut, control)
	if err != nil {
		t.Fatalf("selectPortToRunTest() failed to get a port to run test: %v", err)
	}
	t.Logf("Running test on DUT interface: %v, control interface: %v.", intf, controlIntf)

	err = isLinkUp(t, dut, control, intf, controlIntf)
	if err != nil {
		t.Fatalf("isLinkUp() failed: %v", err)
	}

	// Save the current config on port.
	oldHoldTimeUpDut := fetchLinkEventDampingConfig(t, dut, intf)
	t.Logf("Initial hold-time up config on DUT interface: %v", oldHoldTimeUpDut)
	oldLoopbackModeDut := fetchLoopbackMode(t, dut, intf)
	t.Logf("Initial loopback-mode on DUT interface: %v", oldLoopbackModeDut)
	oldHoldTimeUpControl := fetchLinkEventDampingConfig(t, control, controlIntf)
	t.Logf("Initial hold-time up config on control interface: %v", oldHoldTimeUpControl)

	// Restore the config after the test.
	t.Cleanup(func() {
		restoreConfig(t, dut, control, intf, controlIntf, oldLoopbackModeDut, oldHoldTimeUpDut, oldHoldTimeUpControl)
	})

	// Disable link event damping.
	setLinkEventDampingConfig(t, dut, intf, holdTimeDisableMs)
	setLinkEventDampingConfig(t, control, controlIntf, holdTimeDisableMs)
	time.Sleep(waitAFterLinkEventDampingDisable)
	// Set MAC loopback on port.
	setLoopbackMode(t, dut, intf, loopbackModeEnabled)
	time.Sleep(waitAfterLoopbackModeChange)
	// Get initial carrier transitions.
	initCarrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State())
	t.Logf("Initial carrier transitions: %v", initCarrierTransitions)

	numberOfFlaps := 10
	// Flap the port and collect oper status samples.
	collectTimeout := time.Duration(numberOfFlaps)*(upTransitionNotificationTimeout+downTransitionNotificationTimeout) + 5*time.Second
	operStatusSamples, flapError := flapPortAndCollectOperStatusNotifications(t, dut, intf, numberOfFlaps, true, collectTimeout)
	if flapError != nil {
		t.Errorf("flapPortAndCollectOperStatusNotifications failed on port: %v", flapError)
	} else if len(operStatusSamples) != 2*numberOfFlaps {
		t.Errorf("flapPortAndCollectOperStatusNotifications got %v samples, want %v samples.", len(operStatusSamples), 2*numberOfFlaps)
	}
	finalCarrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State())
	t.Logf("Final carrier transitions: %v", finalCarrierTransitions)

	// Verify the events count.
	carrierTransitions := finalCarrierTransitions - initCarrierTransitions
	if carrierTransitions != uint64(2*numberOfFlaps) {
		t.Errorf("Got: %v carrier transitions but want: %v", carrierTransitions, 2*numberOfFlaps)
	}
}

// Tests that first link flap events on an interface is not damped after
// enabling the link event damping config.
func TestFirstFlapEventsNotDampedAfterLinkEventDampingConfig(t *testing.T) {
	// Report results to TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("a92fd0c4-0461-4379-a8ba-76ce6710d8a4").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	control := ondatra.DUT(t, "CONTROL")
	intf, controlIntf, err := selectPortToRunTest(t, dut, control)
	if err != nil {
		t.Fatalf("selectPortToRunTest() failed to get a port to run test: %v", err)
	}
	t.Logf("Running test on DUT interface: %v, control interface: %v.", intf, controlIntf)

	err = isLinkUp(t, dut, control, intf, controlIntf)
	if err != nil {
		t.Fatalf("isLinkUp() failed: %v", err)
	}

	// Save the current config on port.
	oldHoldTimeUpDut := fetchLinkEventDampingConfig(t, dut, intf)
	t.Logf("Initial hold-time up config on DUT interface: %v", oldHoldTimeUpDut)
	oldLoopbackModeDut := fetchLoopbackMode(t, dut, intf)
	t.Logf("Initial loopback-mode on DUT interface: %v", oldLoopbackModeDut)
	oldHoldTimeUpControl := fetchLinkEventDampingConfig(t, control, controlIntf)
	t.Logf("Initial hold-time up config on control interface: %v", oldHoldTimeUpControl)

	// Restore the config after the test.
	t.Cleanup(func() {
		// Disable link event damping config on port to clear the damped state
		// before restoring the config.
		setLinkEventDampingConfig(t, dut, intf, holdTimeDisableMs)
		time.Sleep(waitAFterLinkEventDampingDisable)
		restoreConfig(t, dut, control, intf, controlIntf, oldLoopbackModeDut, oldHoldTimeUpDut, oldHoldTimeUpControl)
	})

	// Disable link event damping so that damped state is cleared if present.
	setLinkEventDampingConfig(t, dut, intf, holdTimeDisableMs)
	setLinkEventDampingConfig(t, control, controlIntf, holdTimeDisableMs)
	time.Sleep(waitAFterLinkEventDampingDisable)
	// Set MAC loopback on port.
	setLoopbackMode(t, dut, intf, loopbackModeEnabled)
	time.Sleep(waitAfterLoopbackModeChange)
	// Enable link event damping on DUT.
	setLinkEventDampingConfig(t, dut, intf, holdTimeEnableMs)
	// Get initial carrier transitions.
	initCarrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State())
	t.Logf("Initial carrier transitions: %v", initCarrierTransitions)

	// Flap the port and events should not be damped and notified immediately.
	numberOfFlaps := 1
	collectTimeout := time.Duration(numberOfFlaps)*(upTransitionNotificationTimeout+downTransitionNotificationTimeout) + 5*time.Second
	operStatusSamples, flapError := flapPortAndCollectOperStatusNotifications(t, dut, intf, numberOfFlaps, true, collectTimeout)
	if flapError != nil {
		t.Errorf("flapPortAndCollectOperStatusNotifications failed on port: %v", flapError)
	} else if len(operStatusSamples) != 2 {
		t.Errorf("flapPortAndCollectOperStatusNotifications got %v samples, want 2 samples.", len(operStatusSamples))
	}
	if carrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State()); carrierTransitions != initCarrierTransitions+2 {
		t.Errorf("Got: %v carrier transitions but want: %v", carrierTransitions, initCarrierTransitions+2)
	}
}

// Tests that when multiple flaps happen one after another on a port, port
// remains damped.
func TestMultipleFlapsWithLinkEventDampingConfig(t *testing.T) {
	// Report results to TestTracker at the end.
	defer testhelper.NewTearDownOptions(t).WithID("5ccd7b33-8661-4b82-9d19-971816b2aeea").Teardown(t)

	dut := ondatra.DUT(t, "DUT")
	control := ondatra.DUT(t, "CONTROL")
	intf, controlIntf, err := selectPortToRunTest(t, dut, control)
	if err != nil {
		t.Fatalf("selectPortToRunTest() failed to get a port to run test: %v", err)
	}
	t.Logf("Running test on DUT interface: %v, control interface: %v.", intf, controlIntf)

	err = isLinkUp(t, dut, control, intf, controlIntf)
	if err != nil {
		t.Fatalf("isLinkUp() failed: %v", err)
	}

	// Save the current config on port.
	oldHoldTimeUpDut := fetchLinkEventDampingConfig(t, dut, intf)
	t.Logf("Initial hold-time up config on DUT interface: %v", oldHoldTimeUpDut)
	oldLoopbackModeDut := fetchLoopbackMode(t, dut, intf)
	t.Logf("Initial loopback-mode on DUT interface: %v", oldLoopbackModeDut)
	oldHoldTimeUpControl := fetchLinkEventDampingConfig(t, control, controlIntf)
	t.Logf("Initial hold-time up config on control interface: %v", oldHoldTimeUpControl)

	// Restore the config after the test.
	t.Cleanup(func() {
		// Disable link event damping config on port to clear the damped state
		// before restoring the config.
		setLinkEventDampingConfig(t, dut, intf, holdTimeDisableMs)
		time.Sleep(waitAFterLinkEventDampingDisable)
		restoreConfig(t, dut, control, intf, controlIntf, oldLoopbackModeDut, oldHoldTimeUpDut, oldHoldTimeUpControl)
	})

	// Disable link event damping so that damped state is cleared if present.
	setLinkEventDampingConfig(t, dut, intf, holdTimeDisableMs)
	setLinkEventDampingConfig(t, control, controlIntf, holdTimeDisableMs)
	time.Sleep(waitAFterLinkEventDampingDisable)
	// Set MAC loopback on port.
	setLoopbackMode(t, dut, intf, loopbackModeEnabled)
	time.Sleep(waitAfterLoopbackModeChange)
	// Enable link event damping.
	setLinkEventDampingConfig(t, dut, intf, holdTimeEnableMs)
	// Get initial carrier transitions.
	initCarrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State())
	t.Logf("Initial carrier transitions: %v", initCarrierTransitions)

	// First flap events should not be damped after config enable and notified
	// immediately.
	numberOfFlaps := 1
	collectTimeout := time.Duration(numberOfFlaps)*(upTransitionNotificationTimeout+downTransitionNotificationTimeout) + 5*time.Second
	operStatusSamples, flapError := flapPortAndCollectOperStatusNotifications(t, dut, intf, numberOfFlaps, true, collectTimeout)
	if flapError != nil {
		t.Errorf("flapPortAndCollectOperStatusNotifications failed to verify first flap on port: %v", flapError)
	} else if len(operStatusSamples) != 2 {
		t.Errorf("flapPortAndCollectOperStatusNotifications got %v samples, but want 2 samples.", len(operStatusSamples))
	}
	if carrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State()); carrierTransitions != initCarrierTransitions+2 {
		t.Errorf("Got: %v carrier transitions but want: %v", carrierTransitions, initCarrierTransitions+2)
	}
	// DOWN event of second flap should start the damping and DOWN event
	// notification should be observed but UP event will be damped.
	operStatusSamples, flapError = flapPortAndCollectOperStatusNotifications(t, dut, intf, numberOfFlaps, false, collectTimeout)
	if flapError != nil {
		t.Errorf("flapPortAndCollectOperStatusNotifications failed on port: %v", flapError)
	} else if len(operStatusSamples) != 1 {
		t.Errorf("flapPortAndCollectOperStatusNotifications got %v samples, want 1 sample.", len(operStatusSamples))
	}
	if carrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State()); carrierTransitions != initCarrierTransitions+3 {
		t.Errorf("Got: %v carrier transitions but want: %v", carrierTransitions, initCarrierTransitions+3)
	}
	if operStatus := gnmi.Get(t, dut, gnmi.OC().Interface(intf).OperStatus().State()); operStatus != oc.Interface_OperStatus_DOWN {
		t.Errorf("Got %v oper status but want %v.", operStatus, oc.Interface_OperStatus_DOWN)
	}
	// Subsequent flap events should be damped.
	numberOfFlaps = 10
	collectTimeout = time.Duration(numberOfFlaps)*(upTransitionNotificationTimeout+downTransitionNotificationTimeout) + 30*time.Second
	operStatusSamples, flapError = flapPortAndCollectOperStatusNotifications(t, dut, intf, numberOfFlaps, false, collectTimeout)
	if flapError != nil {
		t.Errorf("flapPortAndCollectOperStatusNotifications failed on port: %v", flapError)
	} else if len(operStatusSamples) != 0 {
		t.Errorf("flapPortAndCollectOperStatusNotifications got %v samples, want 0 sample.", len(operStatusSamples))
	}
	if carrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State()); carrierTransitions != initCarrierTransitions+3 {
		t.Errorf("Got: %v carrier transitions but want: %v", carrierTransitions, initCarrierTransitions+3)
	}
	if operStatus := gnmi.Get(t, dut, gnmi.OC().Interface(intf).OperStatus().State()); operStatus != oc.Interface_OperStatus_DOWN {
		t.Errorf("Got %v oper status but want %v.", operStatus, oc.Interface_OperStatus_DOWN)
	}
	// Disable link event damping so that damped state is cleared and UP
	// notification is received.
	setLinkEventDampingConfig(t, dut, intf, holdTimeDisableMs)
	time.Sleep(waitAFterLinkEventDampingDisable)

	if carrierTransitions := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Counters().CarrierTransitions().State()); carrierTransitions != initCarrierTransitions+4 {
		t.Errorf("Got: %v carrier transitions but want: %v", carrierTransitions, initCarrierTransitions+4)
	}
	if operStatus := gnmi.Get(t, dut, gnmi.OC().Interface(intf).OperStatus().State()); operStatus != oc.Interface_OperStatus_UP {
		t.Errorf("Got %v oper status but want %v.", operStatus, oc.Interface_OperStatus_UP)
	}
}

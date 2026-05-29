package module_reset_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"

	syspb "github.com/openconfig/gnoi/system"
	typespb "github.com/openconfig/gnoi/types"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

const (
	waitTimeInterfacesUp = 60 * time.Second
	transceiverPrefix    = "Ethernet"
)

// Enum to represent which modules to reset in each test case.
type testModules int

const (
	oneModule testModules = iota
	allModules
)

func TestResetModules(t *testing.T) {
	dut := ondatra.DUT(t, "DUT")

	// Get all ports connected to peer device.
	var dutPorts []string
	for _, port := range dut.Ports() {
		dutPorts = append(dutPorts, port.Name())
	}

	tests := []struct {
		name    string
		uuid    string
		modules testModules
	}{
		{
			name:    "TestResetOneModule",
			uuid:    "4593ff89-892b-46f7-a049-959c8681912d",
			modules: oneModule,
		},
		{
			name:    "TestResetAllModules",
			uuid:    "af9877f2-40f3-4abe-873b-e1db155a917d",
			modules: allModules,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer testhelper.NewTearDownOptions(t).WithID(tt.uuid).Teardown(t)

			operStatusInfo, err := testhelper.FetchPortsOperStatus(t, dut, dutPorts...)
			if err != nil {
				t.Fatalf("Failed to fetch ports oper status: %v", err)
			}
			upPorts := operStatusInfo.Up
			if len(upPorts) == 0 {
				t.Log("No up ports found at start of test")
			}

			paths := []*typespb.Path{}

			// Name of transceiver to reset, for OneModule test.
			var testXcvr string

			for _, component := range gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().State()) {
				xcvrName := component.GetName()
				// Skip non-transceiver components.
				if !strings.HasPrefix(xcvrName, transceiverPrefix) {
					continue
				}
				if !component.GetEmpty() {
					// Add transceiver name to paths.
					pathElems := []*typespb.PathElem{
						&typespb.PathElem{Name: "components"},
						&typespb.PathElem{Name: "component", Key: map[string]string{"name": xcvrName}},
					}
					path := &typespb.Path{
						Origin: "openconfig",
						Elem:   pathElems,
					}
					paths = append(paths, path)
					if tt.modules == oneModule {
						t.Logf("Testing transceiver %v", xcvrName)
						testXcvr = xcvrName
						break
					}
				}
			}
			if len(paths) == 0 {
				t.Fatal("No non-empty transceivers found")
			}
			req := &syspb.RebootRequest{
				Method:        syspb.RebootMethod_COLD,
				Message:       "Reset transceiver modules",
				Subcomponents: paths,
			}

			params := testhelper.NewRebootParams().WithWaitTime(0 * time.Second).WithCheckInterval(0 * time.Second).WithRequest(req)

			if err := testhelper.Reboot(t, dut, params); err != nil {
				t.Fatalf("Reboot RPC failed: %v", err)
			}

			// If test resets one module, verify that ports on all the other modules are still up.
			if tt.modules == oneModule {
				for _, intf := range upPorts {
					// Verify that interfaces not on testXcvr are up.
					xcvrName := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Transceiver().State())
					if xcvrName != testXcvr {
						if got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).OperStatus().State()); got != oc.Interface_OperStatus_UP {
							t.Errorf("Interface %v oper status is not UP", intf)
						}
					}
				}
			}

			if len(upPorts) > 0 {
				time.Sleep(waitTimeInterfacesUp)
				if err := testhelper.VerifyPortsOperStatus(t, dut, upPorts...); err != nil {
					t.Fatalf("Not all ports are up at the end of the test %v: %v", tt.name, err)
				}
			}
		})
	}
}

func TestResetModuleInvalidTransceiver(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("9b1c5bb4-f79e-4aab-9488-ce7294728abd").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	// Get all ports connected to peer device.
	var dutPorts []string
	for _, port := range dut.Ports() {
		dutPorts = append(dutPorts, port.Name())
	}

	operStatusInfo, err := testhelper.FetchPortsOperStatus(t, dut, dutPorts...)
	if err != nil {
		t.Fatalf("Failed to fetch ports oper status: %v", err)
	}
	upPorts := operStatusInfo.Up
	if len(upPorts) == 0 {
		t.Log("No up ports found at start of test")
	}

	maxXcvrNum := 0

	for _, component := range gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().State()) {
		xcvrName := component.GetName()
		// Skip non-transceiver components.
		if !strings.HasPrefix(xcvrName, transceiverPrefix) {
			continue
		}
		var phyPortNum int
		_, err := fmt.Sscanf(xcvrName, transceiverPrefix+"%d", &phyPortNum)
		if err == nil {
			if phyPortNum > maxXcvrNum {
				maxXcvrNum = phyPortNum
			}
		}
	}
	if maxXcvrNum == 0 {
		t.Fatalf("No transceivers found")
	}

	invalidXcvrName := fmt.Sprintf("Ethernet%v", maxXcvrNum+1)
	t.Logf("Testing with invalid transceiver name %v", invalidXcvrName)

	pathElems := []*typespb.PathElem{
		&typespb.PathElem{Name: "components"},
		&typespb.PathElem{Name: "component", Key: map[string]string{"name": invalidXcvrName}},
	}
	path := &typespb.Path{
		Origin: "openconfig",
		Elem:   pathElems,
	}
	paths := []*typespb.Path{path}

	req := &syspb.RebootRequest{
		Method:        syspb.RebootMethod_COLD,
		Message:       "Reset transceiver",
		Subcomponents: paths,
	}

	params := testhelper.NewRebootParams().WithWaitTime(0 * time.Second).WithCheckInterval(0 * time.Second).WithRequest(req)

	err = testhelper.Reboot(t, dut, params)
	t.Logf("Reboot err: %v", err)

	if err == nil {
		t.Errorf("Reboot RPC expected to fail")
	}
	if len(upPorts) > 0 {
		if err := testhelper.VerifyPortsOperStatus(t, dut, upPorts...); err != nil {
			t.Fatalf("Not all ports are up at the end of the test: %v", err)
		}
	}
}

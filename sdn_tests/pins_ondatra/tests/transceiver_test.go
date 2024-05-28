package transceiver_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygot/ygot"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"google.golang.org/grpc"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func FindPresentTransceiver(t *testing.T, dut *ondatra.DUTDevice) (string, int) {
	for _, xcvrName := range gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().Name().State()) {
		var phyPortNum int
		_, err := fmt.Sscanf(xcvrName, "Ethernet%d", &phyPortNum)
		if err == nil {
			empty := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Empty().State())
			if !empty {
				return xcvrName, phyPortNum
			}
		}
	}
	t.Fatal("No non-empty transceiver found")
	return "", 0
}

func xcvrLanesByXcvrName(t *testing.T, dut *ondatra.DUTDevice, xcvrName string) (uint16, error) {
	formFactor := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Transceiver().FormFactor().State())
	xcvrTypeToLanes := map[oc.E_TransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE]uint16{
		oc.TransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_SFP:       1,
		oc.TransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_SFP_PLUS:  1,
		oc.TransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_QSFP:      4,
		oc.TransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_QSFP_PLUS: 4,
		oc.TransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_OSFP:      8,
	}
	if lane, ok := xcvrTypeToLanes[formFactor]; ok {
		return lane, nil
	}
	return 0, fmt.Errorf("transceiver %v has unsupported form factor %v", xcvrName, formFactor.String())
}

func FindPresentOpticalTransceiver(t *testing.T, dut *ondatra.DUTDevice) (string, int, error) {
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(context.Background(), grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}
	for _, xcvrName := range gnmi.GetAll(t, dut, gnmi.OC().ComponentAny().Name().State()) {
		var phyPortNum int
		_, err := fmt.Sscanf(xcvrName, "Ethernet%d", &phyPortNum)
		if err == nil {
			empty := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Empty().State())
			if !empty {
				optical, err := IsOptical(gnmiClient, dut, xcvrName)
				if err != nil {
					return "", 0, fmt.Errorf("IsOptical failed: %v", err.Error())
				}
				if optical {
					return xcvrName, phyPortNum, nil
				}
			}
		}
	}
	return "", 0, nil
}

// Check if a transceiver is optical by getting cable-length,
// which should only be positive only for copper tranceivers.
// If cable-length is 0, then the transceiver is optical.
// Since cable-length is only defined in buzznik's
// openconfig-platform-ext.yang which is unavailable to Ondatra,
// it is necessary to use raw gNMI get.
func IsOptical(gnmiClient gpb.GNMIClient, dut *ondatra.DUTDevice, xcvrName string) (bool, error) {
	prefix := &gpb.Path{Origin: "openconfig", Target: dut.Name()}
	sPath, err := ygot.StringToStructuredPath("components/component[name=" + xcvrName + "]/transceiver/state/openconfig-platform-ext:cable-length")
	if err != nil {
		return false, fmt.Errorf("Unable to convert string to path (%v)", err)
	}
	paths := []*gpb.Path{sPath}
	getRequest := &gpb.GetRequest{
		Prefix:   prefix,
		Path:     paths,
		Type:     gpb.GetRequest_STATE,
		Encoding: gpb.Encoding_PROTO,
	}
	ctx := context.Background()
	getResp, err := gnmiClient.Get(ctx, getRequest)
	if err != nil {
		return false, fmt.Errorf("Unable to fetch get client (%v)", err)
	}
	if getResp == nil {
		return false, fmt.Errorf("Unable to fetch get client, get response is nil")
	}
	notifs := getResp.GetNotification()
	if len(notifs) != 1 {
		return false, fmt.Errorf("got %d notifications, want 1", len(notifs))
	}
	notif := notifs[0]
	updates := notif.GetUpdate()
	if len(updates) != 1 {
		return false, fmt.Errorf("got %d updates in the notification, want 1", len(updates))
	}
	val := updates[0].GetVal()
	return val.GetFloatVal() == 0, nil
}

func TestReadName(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("bbdc5e8b-8182-4a55-a7bd-11fc206aedc2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	xcvrName, _ := FindPresentTransceiver(t, dut)

	telemetryNamePath := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Name().State())
	if xcvrName != telemetryNamePath {
		t.Errorf("Component key name (%v) does not match telemetry name path value: %v", xcvrName, telemetryNamePath)
	}

	configNamePath := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Name().Config())
	if xcvrName != configNamePath {
		t.Errorf("Component key name (%v) does not match config name path value: %v", xcvrName, configNamePath)
	}
}

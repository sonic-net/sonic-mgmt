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

func TestIndex(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("2e63771a-4414-459b-a4ef-d56ed0de6a7a").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	xcvrName, _ := FindPresentTransceiver(t, dut)
	t.Logf("Transceiver found: %v", xcvrName)

	numChannels, err := xcvrLanesByXcvrName(t, dut, xcvrName)
	if err != nil {
		t.Fatalf("%v", err)
	}

	for channel := uint16(0); channel < numChannels; channel++ {
		if channel != gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Transceiver().Channel(channel).Index().State()) {
			t.Errorf("Failed to get telemetry channel index %v", channel)
		}
		if channel != gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Transceiver().Channel(channel).Index().Config()) {
			t.Errorf("Failed to get config channel index %v", channel)
		}
	}

	// TODO: uncomment after bug is fixed.
	// Out-of-range get index should fail.
	// testt.ExpectError(t, func(t testing.TB) {
	//	dutTelemetry.Component(xcvrName).Transceiver().Channel(numChannels).Index().Get(t)
	// })
}

func TestReadTransceiverStaticData(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("5b255989-eb9d-4587-922f-160b9a011cf1").Teardown(t)

	dut := ondatra.DUT(t, "DUT")

	xcvrName, xcvrNum := FindPresentTransceiver(t, dut)

	if len(gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).MfgName().State())) == 0 {
		t.Errorf("Transceiver %v MfgName is empty", xcvrName)
	}
	if len(gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).PartNo().State())) == 0 {
		t.Errorf("Transceiver %v PartNo is empty", xcvrName)
	}
	if len(gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).SerialNo().State())) == 0 {
		t.Errorf("Transceiver %v SerialNo is empty", xcvrName)
	}
	if len(gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).FirmwareVersion().State())) == 0 {
		t.Errorf("Transceiver %v FirmwareVersion is empty", xcvrName)
	}
	if len(testhelper.GetLatestAvailableFirmwareVersion(t, dut, xcvrName)) == 0 {
		t.Errorf("Transceiver %v LatestAvailableFirmwareVersion is empty", xcvrName)
	}

	// Get() API for leaf nodes verifies that value complies with the format,
	// specified in the YANG model, which will verify that the
	// date is in YYYY-MM-DD format.
	gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).MfgDate().State())

	if ethernetPmd := testhelper.EthernetPMD(t, dut, xcvrName); ethernetPmd == "ETH_UNDEFINED" {
		t.Errorf("Transceiver %v has undefined PMD type", xcvrName)
	}

	componentType := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Type().State())

	if componentType != oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_TRANSCEIVER {
		t.Errorf("Transceiver %v has incorrect component type: %v, should be TRANSCEIVER", xcvrName, componentType)
	}

	expectedParent := fmt.Sprintf("1/%v", xcvrNum)
	parent := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Parent().State())
	if parent != expectedParent {
		t.Errorf("Transceiver (%v) parent match failed! got:%v, want:%v", xcvrName, parent, expectedParent)
	}
}

// TODO: Move platform-specific constants to testhelper.
// These ranges are arbitrary, and not necessarily the operational range for production.
const (
	minTemp          = 10.0
	maxTemp          = 55.0
	minPower         = -30.0
	maxPower         = 10.0
	unsupportedPower = -40.0
)

// TODO: Once SetTransceiverState is implemented and supported in gNMI,
// and xcvrd threading issues are fixed, also test that input-power changes.
func TestReadTransceiverDynamicData(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("31c2b81d-a3b5-4841-a2ad-da4bcc1f4a8f").Teardown(t)
	dut := ondatra.DUT(t, "DUT")

	xcvrName, _, err := FindPresentOpticalTransceiver(t, dut)

	if err != nil {
		t.Fatalf("FindPresentOpticalTransceiver failed, %v", err.Error())
	}

	if xcvrName == "" {
		t.Log("No optical transceiver found, skipping test")
		t.Skip()
	} else {
		t.Logf("Testing transceiver %v", xcvrName)
	}

	temperature := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Temperature().Instant().State())
	if temperature < minTemp || temperature > maxTemp {
		t.Errorf("Transceiver temperature is %v, should be in range 10C-55C", temperature)
	}

	numChannels, err := xcvrLanesByXcvrName(t, dut, xcvrName)
	if err != nil {
		t.Fatalf("%v", err)
	}

	for channel := uint16(0); channel < numChannels; channel++ {
		laserBiasCurrent := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Transceiver().Channel(channel).LaserBiasCurrent().Instant().State())
		if laserBiasCurrent <= 0.0 {
			t.Errorf("Laser bias current for channel %v is %v, should be positive", channel, laserBiasCurrent)
		}
		inputPower := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Transceiver().Channel(channel).InputPower().Instant().State())
		if inputPower < minPower || inputPower > maxPower {
			t.Errorf("Input power for channel %v is %v, should be in range [%v, %v]", channel, inputPower, minPower, maxPower)
		}
		outputPower := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).Transceiver().Channel(channel).OutputPower().Instant().State())

		// Output power is not supported on some modules: if unsupported, the value is reported as -40.
		// Skip testing output power in this case.
		if (outputPower != unsupportedPower) && (outputPower < minPower || outputPower > maxPower) {
			t.Errorf("Output power for channel %v is %v, should be in range [%v, %v]", channel, outputPower, minPower, maxPower)
		}
	}

}

func TestReadParentPath(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("0057ca44-0cbc-4054-a20c-94bc99e9b984").Teardown(t)

	dut := ondatra.DUT(t, "DUT")

	xcvrName, xcvrNum := FindPresentTransceiver(t, dut)

	transceiver := gnmi.Get(t, dut, gnmi.OC().Component(xcvrName).State())

	transceiverPathName := transceiver.GetName()
	if transceiverPathName != xcvrName {
		t.Errorf("Transceiver parent path name got: %v, want: %v", transceiverPathName, xcvrName)
	}

	if len(transceiver.GetMfgName()) == 0 {
		t.Errorf("Transceiver %v MfgName is empty", xcvrName)
	}

	mfgDate := transceiver.GetMfgDate()
	dateMatched, err := regexp.MatchString(`^\d\d\d\d-\d\d-\d\d$`, mfgDate)
	if err != nil {
		t.Errorf("MatchString for MfgDate failed: %v", err)
	} else if !dateMatched {
		t.Errorf("MfgDate is %v, should be in format YYYY-MM-DD", mfgDate)
	}

	if len(transceiver.GetPartNo()) == 0 {
		t.Errorf("Transceiver %v SerialNo is empty", xcvrName)
	}
	if len(transceiver.GetSerialNo()) == 0 {
		t.Errorf("Transceiver %v PartNo is empty", xcvrName)
	}
	if len(transceiver.GetFirmwareVersion()) == 0 {
		t.Errorf("Transceiver %v FirmwareVersion is empty", xcvrName)
	}
	if len(testhelper.GetLatestAvailableFirmwareVersion(t, dut, xcvrName)) == 0 {
		t.Errorf("Transceiver %v LatestAvailableFirmwareVersion is empty", xcvrName)
	}

	componentType := transceiver.GetType()
	if componentType != oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_TRANSCEIVER {
		t.Errorf("Transceiver %v has incorrect component type: %v, should be TRANSCEIVER", xcvrName, componentType)
	}

	expectedParent := fmt.Sprintf("1/%v", xcvrNum)
	parent := transceiver.GetParent()
	if parent != expectedParent {
		t.Errorf("Transceiver (%v) parent match failed! got:%v, want:%v", xcvrName, parent, expectedParent)
	}

	numChannels, err := xcvrLanesByXcvrName(t, dut, xcvrName)
	if err != nil {
		t.Fatalf("%v", err)
	}

	for channel := uint16(0); channel < numChannels; channel++ {
		if channel != transceiver.GetTransceiver().GetChannel(channel).GetIndex() {
			t.Errorf("Failed to get channel index %v", channel)
		}
	}
}

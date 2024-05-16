// Package testhelper contains APIs that help in writing GPINs Ondatra tests.
package testhelper

import (
	"crypto/rand"
	"math/big"
	"fmt"
	"strings"
	"testing"
	"time"

	log "github.com/golang/glog"
	healthzpb "github.com/openconfig/gnoi/healthz"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/pkg/errors"
)

var pph portPmdHandler

// Function pointers that interact with the switch. They enable unit testing
// of methods that interact with the switch.
var (
	testhelperIntfOperStatusGet = func(t *testing.T, d *ondatra.DUTDevice, port string) oc.E_Interface_OperStatus {
		return gnmi.Get(t, d, gnmi.OC().Interface(port).OperStatus().State())
	}

	testhelperAllIntfNameGet = func(t *testing.T, d *ondatra.DUTDevice) []string {
		return gnmi.GetAll(t, d, gnmi.OC().InterfaceAny().Name().State())
	}

	testhelperDUTNameGet = func(d *ondatra.DUTDevice) string {
		return d.Name()
	}

	testhelperDUTPortGet = func(t *testing.T, d *ondatra.DUTDevice, id string) *ondatra.Port {
		return d.Port(t, id)
	}

	testhelperDUTPortsGet = func(d *ondatra.DUTDevice) []*ondatra.Port {
		return d.Ports()
	}

	testhelperConfigIntfAggregateIDGet = func(t *testing.T, d *ondatra.DUTDevice, port string) string {
		return gnmi.Get(t, d, gnmi.OC().Interface(port).Ethernet().AggregateId().Config())
	}

	testhelperIntfAggregateIDReplace = func(t *testing.T, d *ondatra.DUTDevice, port string, ID string) {
		gnmi.Replace(t, d, gnmi.OC().Interface(port).Ethernet().AggregateId().Config(), ID)
	}

	testhelperIntfPhysicalChannelsGet = func(t *testing.T, d *ondatra.DUTDevice, port string) []uint16 {
		return gnmi.Get(t, d, gnmi.OC().Interface(port).PhysicalChannel().State())
	}

	testhelperIntfOperStatusAwait = func(t *testing.T, d *ondatra.DUTDevice, port string, expectedOperSatus oc.E_Interface_OperStatus, timeout time.Duration) (oc.E_Interface_OperStatus, bool) {
		predicate := func(val *ygnmi.Value[oc.E_Interface_OperStatus]) bool {
			status, present := val.Val()
			return present && status == expectedOperSatus
		}
		lastVal, match := gnmi.Watch(t, d, gnmi.OC().Interface(port).OperStatus().State(), timeout, predicate).Await(t)
		lastStatus, _ := lastVal.Val()
		return lastStatus, match
	}

	testhelperIntfDelete = func(t *testing.T, d *ondatra.DUTDevice, port string) {
		gnmi.Delete(t, d, gnmi.OC().Interface(port).Config())
	}

	testhelperIntfLookup = func(t *testing.T, d *ondatra.DUTDevice, port string) *ygnmi.Value[*oc.Interface] {
		return gnmi.Lookup(t, d, gnmi.OC().Interface(port).State())
	}

	testhelperIntfHardwarePortGet = func(t *testing.T, d *ondatra.DUTDevice, port string) string {
		return gnmi.Get(t, d, gnmi.OC().Interface(port).HardwarePort().State())
	}

	testhelperConfigPortSpeedGet = func(t *testing.T, d *ondatra.DUTDevice, portName string) oc.E_IfEthernet_ETHERNET_SPEED {
		return gnmi.Get(t, d, gnmi.OC().Interface(portName).Ethernet().PortSpeed().Config())
	}

	testhelperStatePortSpeedGet = func(t *testing.T, d *ondatra.DUTDevice, portName string) oc.E_IfEthernet_ETHERNET_SPEED {
		return gnmi.Get(t, d, gnmi.OC().Interface(portName).Ethernet().PortSpeed().State())
	}

	testhelperOndatraPortNameGet = func(p *ondatra.Port) string {
		return p.Name()
	}

	testhelperOndatraPortIDGet = func(p *ondatra.Port) string {
		return p.ID()
	}

	teardownDUTNameGet = func(t *testing.T) string {
		return ondatra.DUT(t, "DUT").Name()
	}

	teardownDUTDeviceInfoGet = func(t *testing.T) DUTInfo {
		dut := ondatra.DUT(t, "DUT")
		return DUTInfo{
			name:   dut.Name(),
			vendor: dut.Vendor(),
		}
	}

	teardownDUTPeerDeviceInfoGet = func(t *testing.T) DUTInfo {
		duts := ondatra.DUTs(t)
		if len(duts) <= 1 {
			return DUTInfo{}
		}

		if peer, ok := duts["CONTROL"]; ok {
			return DUTInfo{
				name:   peer.Name(),
				vendor: peer.Vendor(),
			}
		}
		return DUTInfo{}
	}

	teardownDUTHealthzGet = func(t *testing.T) healthzpb.HealthzClient {
		return ondatra.DUT(t, "DUT").RawAPIs().GNOI(t).Healthz()
	}

	teardownDUTPeerHealthzGet = func(t *testing.T) healthzpb.HealthzClient {
		return ondatra.DUT(t, "CONTROL").RawAPIs().GNOI(t).Healthz()
	}

	testhelperBreakoutModeGet = func(t *testing.T, d *ondatra.DUTDevice, physicalPort string) *oc.Component_Port_BreakoutMode {
		return gnmi.Get(t, d, gnmi.OC().Component(physicalPort).Port().BreakoutMode().State())
	}

	testhelperPortPmdTypeGet = func(t *testing.T, d *ondatra.DUTDevice, port string) (string, error) {
		if pph.PortToTransceiver == nil {
			pph.PortToTransceiver = make(map[string]string)
		}

		xcvr := ""
		if pph.PortToTransceiver[port] == "" {
			xcvr = PortTransceiver(t, d, port)
			if xcvr == "" {
				return "", fmt.Errorf("transceiver not found for %v:%v", d.Name(), port)
			}
			pph.PortToTransceiver[port] = xcvr
		}

		pmd := string(EthernetPMD(t, d, xcvr))
		if pmd == "" {
			return "", fmt.Errorf("pmd not found for transceiver:%v", xcvr)
		}
		return pmd, nil
	}

	testhelperTransceiverEmpty = func(t *testing.T, d *ondatra.DUTDevice, port string) bool {
		return gnmi.Get(t, d, gnmi.OC().Component(port).Empty().State())
	}
)

// FrontPanelPortPrefix defines prefix string for front panel ports.
const (
	FrontPanelPortPrefix = "Ethernet"
)

// RandomInterfaceParams contains optional list of parameters than can be passed to RandomInterface():
// PortList: If passed, only ports in this list must be considered when picking a random interface.
// IsParent: If set, only parent ports must be considered.
// OperDownOk: If set, then operationally down ports can also be picked.
type RandomInterfaceParams struct {
	PortList   []string
	IsParent   bool
	OperDownOk bool
}

// OperStatusInfo returns the list of interfaces with the following oper-status:
// 1) UP
// 2) DOWN
// 3) TESTING
// 4) Any other value
type OperStatusInfo struct {
	Up      []string
	Down    []string
	Testing []string
	Invalid []string
}

// DUTInfo contains dut related info.
type DUTInfo struct {
	name   string
	vendor ondatra.Vendor
}

// NewDUTInfo creates the DUTInfo structure for a given DUTDevice
func NewDUTInfo(t *testing.T, dut *ondatra.DUTDevice) DUTInfo {
	return DUTInfo{
		name:   dut.Name(),
		vendor: dut.Vendor(),
	}
}

// TearDownOptions consist of the options to be taken into account by the teardown method.
type TearDownOptions struct {
	StartTime         time.Time
	DUTName           string
	IDs               []string
	DUTDeviceInfo     DUTInfo
	DUTPeerDeviceInfo DUTInfo
	SaveLogs          func(t *testing.T, savePrefix string, dut, peer DUTInfo)
}

// NewTearDownOptions creates the TearDownOptions structure with default values.
func NewTearDownOptions(t *testing.T) TearDownOptions {
	return TearDownOptions{
		StartTime:         time.Now(),
		DUTName:           teardownDUTNameGet(t),
		DUTDeviceInfo:     teardownDUTDeviceInfoGet(t),
		DUTPeerDeviceInfo: teardownDUTPeerDeviceInfoGet(t),
	}
}

// WithID attaches an ID to the test.
func (o TearDownOptions) WithID(id string) TearDownOptions {
	o.IDs = append(o.IDs, id)
	return o
}

// WithIDs attaches a list of IDs to the test.
func (o TearDownOptions) WithIDs(ids []string) TearDownOptions {
	for _, id := range ids {
		o.IDs = append(o.IDs, id)
	}
	return o
}

// TearDown provides an interface to implement the teardown routine.
type TearDown interface {
	Teardown(t *testing.T)
}

// infoHandler is a holder for populateInfoHandlers interface.
type infoHandler struct{}

// RandomInterface picks a random front panel port which is operationally UP.
// Many tests typically need a link that is up, so we'll return
// a randomly selected interface if it is Operationally UP. Options can be passed
// to this method using RandomInterfaceParams struct.
func RandomInterface(t *testing.T, dut *ondatra.DUTDevice, params *RandomInterfaceParams) (string, error) {
	// Parse additional parameters
	var portList []string
	isParent := false
	isOperDownOk := false
	if params != nil {
		portList = params.PortList
		isParent = params.IsParent
		isOperDownOk = params.OperDownOk
	}

	info, err := FetchPortsOperStatus(t, dut, portList...)
	if err != nil || info == nil {
		return "", errors.Wrap(err, "failed to fetch ports oper-status")
	}

	// By default this API considers only operationally UP ports.
	interfaces := info.Up
	if isOperDownOk {
		interfaces = append(interfaces, info.Down...)
	}

	if isParent {
		// Pick parent port only.
		var parentInterfaces []string
		for _, intf := range interfaces {
			isParentPort, err := IsParentPort(t, dut, intf)
			if err != nil {
				return "", errors.Wrapf(err, "IsParentPort() failed for port: %v", intf)
			}
			if isParentPort {
				parentInterfaces = append(parentInterfaces, intf)
			}
		}
		interfaces = parentInterfaces
	}

	if len(interfaces) == 0 {
		if params == nil {
			return "", errors.Errorf("no operationally UP interfaces found in %v", testhelperDUTNameGet(dut))
		}
		return "", errors.Errorf("no interface found in %v with params: %+v", testhelperDUTNameGet(dut), *params)
	}
	interfaceLen := int64(len(interfaces))
	max := big.NewInt(interfaceLen)
	randomIndex, _ := rand.Int(rand.Reader, max)
	s := interfaces[randomIndex.Int64()]

	log.Infof("Using interface %v (%d considered)", s, len(interfaces))
	return s, nil
}

// FetchPortsOperStatus fetches the oper-status of the specified front
// panel ports. If front panel ports are not specified, then it fetches the
// oper-status for all ports on the device. It returns the list of ports with
// oper-status values present in OperStatusInfo struct.
func FetchPortsOperStatus(t *testing.T, d *ondatra.DUTDevice, ports ...string) (*OperStatusInfo, error) {
	if len(ports) == 0 {
		var err error
		ports, err = FrontPanelPortListForDevice(t, d)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch front panel ports")
		}
	}

	operStatusInfo := &OperStatusInfo{}
	for _, port := range ports {
		switch operStatus := testhelperIntfOperStatusGet(t, d, port); operStatus {
		case oc.Interface_OperStatus_UP:
			operStatusInfo.Up = append(operStatusInfo.Up, port)
		case oc.Interface_OperStatus_DOWN:
			operStatusInfo.Down = append(operStatusInfo.Down, port)
		case oc.Interface_OperStatus_TESTING:
			operStatusInfo.Testing = append(operStatusInfo.Testing, port)
		default:
			operStatusInfo.Invalid = append(operStatusInfo.Invalid, port)
		}
	}

	return operStatusInfo, nil
}

// VerifyPortsOperStatus verifies that the oper-status of the specified front
// panel ports is up. If front panel ports are not specified, then it verifies
// the oper-status for all ports on the device.
func VerifyPortsOperStatus(t *testing.T, d *ondatra.DUTDevice, ports ...string) error {
	i, err := FetchPortsOperStatus(t, d, ports...)
	if err != nil {
		return errors.Wrap(err, "failed to fetch ports oper-status")
	}
	if len(i.Down) > 0 || len(i.Testing) > 0 || len(i.Invalid) > 0 {
		return errors.Errorf("some interfaces are not operationally up: %+v", *i)
	}
	return nil
}

// IsFrontPanelPort returns true if the specified port is a front panel port.
func IsFrontPanelPort(port string) bool {
	return strings.HasPrefix(port, FrontPanelPortPrefix)
}

// FrontPanelPortListForDevice returns the list of front panel ports on the switch.
func FrontPanelPortListForDevice(t *testing.T, dut *ondatra.DUTDevice) ([]string, error) {
	var frontPanelPortList []string
	// Filter-out non-front panel ports.
	for _, port := range testhelperAllIntfNameGet(t, dut) {
		if IsFrontPanelPort(port) {
			frontPanelPortList = append(frontPanelPortList, port)
		}
	}
	if len(frontPanelPortList) == 0 {
		return nil, errors.New("no front panel port found")
	}

	return frontPanelPortList, nil
}

// Returns platform-specific information.
func platformInfoForDevice(t *testing.T, dut *ondatra.DUTDevice) (*PlatformInfo, error) {
	return NewPlatformInfo(t, dut, "default")
}

// Returns port-specific information.
func portInfoForDevice(t *testing.T, dut *ondatra.DUTDevice) (*PortInfo, error) {
	// Populate port properties statically for front panel ports.
	return NewPortInfo(t, dut, "default")
}

// WrapError wraps a new error with new line or creates a new error if
// err == nil. It has been created because errors.Wrapf() returns nil
// if err == nil.
func WrapError(err error, format string, args ...any) error {
	format = format + "\n"
	if err == nil {
		return errors.Errorf(format, args...)
	}
	return errors.Wrapf(err, format, args...)
}

// DUTPortNames returns the port names of the DUT.
func DUTPortNames(dut *ondatra.DUTDevice) []string {
	var portNames []string
	for _, port := range testhelperDUTPortsGet(dut) {
		portNames = append(portNames, testhelperOndatraPortNameGet(port))
	}
	return portNames
}

// populatePortPMDInfo provides api to return list of ports with given pmd type from a set of ports.
type populatePortPMDInfo interface {
	portsOfPmdType(dutName string, portNames []string, pmdType oc.E_TransportTypes_ETHERNET_PMD_TYPE) ([]string, error)
}

// portPmdHandler holds the mapping from port names to transceiver.
type portPmdHandler struct {
	PortToTransceiver map[string]string
}

func (p portPmdHandler) portPmdType(dutName string, port string) (oc.E_TransportTypes_ETHERNET_PMD_TYPE, error) {
	return oc.TransportTypes_ETHERNET_PMD_TYPE_ETH_UNDEFINED, nil
}

func (p portPmdHandler) portsOfPmdType(dutName string, portNames []string, pmdType oc.E_TransportTypes_ETHERNET_PMD_TYPE) ([]string, error) {
	var ports []string
	return ports, nil
}

// AvailablePortsOfPMDType returns ports with matching PMD type.
func AvailablePortsOfPMDType(t *testing.T, d *ondatra.DUTDevice, pmdType oc.E_TransportTypes_ETHERNET_PMD_TYPE) ([]string, error) {
	if pph.PortToTransceiver == nil {
		pph.PortToTransceiver = make(map[string]string)
	}
	for _, port := range DUTPortNames(d) {
		if pph.PortToTransceiver[port] == "" {
			pph.PortToTransceiver[port] = gnmi.Get(t, d, gnmi.OC().Interface(port).Transceiver().State())
		}
	}
	return pph.portsOfPmdType(d.Name(), DUTPortNames(d), pmdType)
}

package mgmt_interface_test

// This suite of tests exercises the gNMI paths associated with the management

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/testt"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

var (
	bond0Name            = "bond0"
	interfaceIndex       = uint32(0)
	calledMockConfigPush = false
	managementInterfaces = []string{
		bond0Name,
	}
)

type ipAddressInfo struct {
	address      string
	prefixLength uint8
}

func fetchMgmtIPv4AddressAndPrefix(t *testing.T) (ipAddressInfo, error) {
	// Reads the existing management interface IPv4 address.  For these tests,
	// we will not be able to change the address without breaking connection of
	// the proxy used by the test.
	dut := ondatra.DUT(t, "DUT")
	ipInfo := gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv4().State())
	for _, v := range ipInfo.Address {
		addr := v.GetIp()
		if addr == "" {
			continue
		}
		return ipAddressInfo{address: addr, prefixLength: v.GetPrefixLength()}, nil
	}
	return ipAddressInfo{}, errors.New("no IPv4 management interface has been configured")
}

func fetchMgmtIPv6AddressAndPrefix(t *testing.T) (ipAddressInfo, error) {
	// Reads the existing management interface IPv6 address.  For these tests,
	// we will not be able to change the address without breaking connection of
	// the proxy used by the test.
	dut := ondatra.DUT(t, "DUT")
	ipInfo := gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv6().State())
	for _, v := range ipInfo.Address {
		addr := v.GetIp()
		if addr == "" {
			continue
		}
		return ipAddressInfo{address: addr, prefixLength: v.GetPrefixLength()}, nil
	}
	return ipAddressInfo{}, errors.New("no IPv6 management interface has been configured")
}

func mockConfigPush(t *testing.T) {
	// Performs a mock config push by ensuring the management interface database
	// entries expected for IPv4 and IPv6 addresses have been setup.
	// TODO: Remove calls to this function once the helper function
	// to perform a default config during setup is available.
	dut := ondatra.DUT(t, "DUT")
	d := &oc.Root{}

	// Create the bond0 interface.
	if !calledMockConfigPush {
		t.Logf("Config push for %v", bond0Name)
		newIface := d.GetOrCreateInterface(bond0Name)
		newIface.Name = &bond0Name
		newIface.Type = oc.IETFInterfaces_InterfaceType_ieee8023adLag
		gnmi.Replace(t, dut, gnmi.OC().Interface(bond0Name).Config(), newIface)
		calledMockConfigPush = true
	}
}

// -----------------------------------------------------------------------------
// Generic management interface path tests
// -----------------------------------------------------------------------------

func TestGetInterfaceDefaultInfo(t *testing.T) {
	// This test confirms generic management interface information is correct.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/ethernet/state/mac-address
	//   /interfaces/interface[name=<mgmt>]/state/name
	//   /interfaces/interface[name=<mgmt>]/state/oper-status
	//   /interfaces/interface[name=<mgmt>]/state/type
	defer testhelper.NewTearDownOptions(t).WithID("1b0707dd-4112-4c0f-ad74-1998df876747").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	for _, iface := range managementInterfaces {
		mgmtInterface := gnmi.OC().Interface(iface)
		macAddress := gnmi.Get(t, dut, mgmtInterface.Ethernet().MacAddress().State())
		if _, err := net.ParseMAC(macAddress); err != nil {
			t.Errorf("MGMT component (%v) has invalid mac-address format! got:%v: %v", iface, macAddress, err)
		}
		if mgmtName := gnmi.Get(t, dut, mgmtInterface.Name().State()); mgmtName != iface {
			t.Errorf("MGMT component (%v) name match failed! got:%v, want:%v", iface, mgmtName, iface)
		}
		if operStatus, statusWant := gnmi.Get(t, dut, mgmtInterface.OperStatus().State()), oc.Interface_OperStatus_UP; operStatus != statusWant {
			t.Errorf("MGMT component (%v) oper-status match failed! got:%v, want:%v", iface, operStatus, statusWant)
		}
		if ifaceType, typeWant := gnmi.Get(t, dut, mgmtInterface.Type().State()), oc.IETFInterfaces_InterfaceType_ieee8023adLag; ifaceType != typeWant {
			t.Errorf("MGMT component (%v) type match failed! got:%v, want:%v", iface, ifaceType, typeWant)
		}
	}
}

func TestSetName(t *testing.T) {
	// This test confirms the name of a management interface can be written.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/config/name
	//   /interfaces/interface[name=<mgmt>]/state/name
	defer testhelper.NewTearDownOptions(t).WithID("826882ed-0534-499c-880a-91cb3c078a03").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	mgmtInterfaceState := gnmi.OC().Interface(bond0Name)
	mgmtInterfaceConfig := gnmi.OC().Interface(bond0Name)

	gnmi.Replace(t, dut, mgmtInterfaceConfig.Name().Config(), bond0Name)
	gnmi.Await(t, dut, mgmtInterfaceState.Name().State(), 5*time.Second, bond0Name)

	// Expect name on state path to have changed.
	if configuredName := gnmi.Get(t, dut, mgmtInterfaceConfig.Name().Config()); configuredName != bond0Name {
		t.Errorf("MGMT component (%v) name match failed! set:%v, config-path-value:%v (want:%v)", bond0Name, bond0Name, configuredName, bond0Name)
	}
}

func TestSetInvalidType(t *testing.T) {
	// This test confirms that an invalid type cannot be set for the management
	// interface.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/config/type
	//   /interfaces/interface[name=<mgmt>]/state/type
	defer testhelper.NewTearDownOptions(t).WithID("0c838fb4-6846-4f5e-a5db-cbcabacdb020").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	for _, iface := range managementInterfaces {
		mgmtInterfaceState := gnmi.OC().Interface(iface)
		mgmtInterfaceConfig := gnmi.OC().Interface(iface)
		originalType := gnmi.Get(t, dut, mgmtInterfaceState.Type().State())
		originalConfigType := gnmi.Get(t, dut, mgmtInterfaceConfig.Type().Config())

		invalidType := oc.IETFInterfaces_InterfaceType_softwareLoopback
		// This call should fail, since the type is invalid for a management interface.
		testt.ExpectFatal(t, func(t testing.TB) {
			gnmi.Replace(t, dut, mgmtInterfaceConfig.Type().Config(), invalidType)
		})
		stateType := gnmi.Get(t, dut, mgmtInterfaceState.Type().State())
		configuredType := gnmi.Get(t, dut, mgmtInterfaceConfig.Type().Config())

		// Invalid type should not have gone through.
		if stateType != originalType || configuredType == invalidType {
			t.Errorf("MGMT component (%v) type match failed! set:%v, config-path-value:%v (want:%v), state-path-value:%v (want:%v)", iface, invalidType, configuredType, originalConfigType, stateType, originalType)
		}
	}
}

func TestSetInvalidName(t *testing.T) {
	// This test confirms that an invalid name cannot be set for the management
	// interface.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/config/name
	//   /interfaces/interface[name=<mgmt>]/state/name
	defer testhelper.NewTearDownOptions(t).WithID("67a8c951-34cc-4148-9f09-a779e7976d03").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	mgmtInterfaceState := gnmi.OC().Interface(bond0Name)
	mgmtInterfaceConfig := gnmi.OC().Interface(bond0Name)
	originalName := gnmi.Get(t, dut, mgmtInterfaceState.Name().State())
	originalConfigName := gnmi.Get(t, dut, mgmtInterfaceConfig.Name().Config())

	invalidName := "mybond0"
	// Setting invalid name should be ignored.
	// TODO: This replace call should fail.
	gnmi.Replace(t, dut, mgmtInterfaceConfig.Name().Config(), invalidName)
	gnmi.Await(t, dut, mgmtInterfaceState.Name().State(), 5*time.Second, originalName)

	// Invalid name should not be accepted.
	if configuredName := gnmi.Get(t, dut, mgmtInterfaceConfig.Name().Config()); configuredName == invalidName {
		t.Errorf("MGMT component (%v) name match failed! set:%v, config-path-value:%v (want:%v)", bond0Name, invalidName, configuredName, originalConfigName)
	}
}

// -----------------------------------------------------------------------------
// Counter path tests
// -----------------------------------------------------------------------------

func verifyInCounters(counters *oc.Interface_Counters) []error {
	var rv []error
	if counters.InDiscards == nil {
		rv = append(rv, errors.New("in-discards"))
	}
	if counters.InErrors == nil {
		rv = append(rv, errors.New("in-errors"))
	}
	if counters.InOctets == nil {
		rv = append(rv, errors.New("in-octets"))
	}
	if counters.InPkts == nil {
		rv = append(rv, errors.New("in-pkts"))
	}
	return rv
}

func verifyOutCounters(counters *oc.Interface_Counters) []error {
	var rv []error
	if counters.OutDiscards == nil {
		rv = append(rv, errors.New("out-discards"))
	}
	if counters.OutErrors == nil {
		rv = append(rv, errors.New("out-errors"))
	}
	if counters.OutOctets == nil {
		rv = append(rv, errors.New("out-octets"))
	}
	if counters.OutPkts == nil {
		rv = append(rv, errors.New("out-pkts"))
	}
	return rv
}

func TestInCounters(t *testing.T) {
	// This test confirms that the input counters (RX side) are updated by packet
	// events.  Note: the management interface is the connection by which gNMI
	// operations take place, so it is difficult to get a precise count of the
	// expected differences in counter values.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/state/counters/in-discards
	//   /interfaces/interface[name=<mgmt>]/state/counters/in-errors
	//   /interfaces/interface[name=<mgmt>]/state/counters/in-octets
	//   /interfaces/interface[name=<mgmt>]/state/counters/in-pkts
	defer testhelper.NewTearDownOptions(t).WithID("b0801966-fb60-456d-9c91-ee3191c5e7e1").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	counters := gnmi.OC().Interface(bond0Name).Counters()
	initialState := gnmi.Get(t, dut, counters.State())
	if errors := verifyInCounters(initialState); len(errors) != 0 {
		t.Fatalf("MGMT component (%v) has invalid initial input counters: %v", bond0Name, errors)
	}

	t.Logf("Initial in-counters state has:")
	t.Logf("  in-discards:%v  in-errors:%v  in-octets:%v  in-pkts: %v", initialState.GetInDiscards(), initialState.GetInErrors(), initialState.GetInOctets(), initialState.GetInPkts())

	// The management interface is active.  That is how gNMI operations are
	// communicated to the switch.  In this test, we verify that packets have been
	// received and that there were no errors.
	// Initiate a handful of Get operations to ensure there is traffic.
	gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Name().State())
	gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Name().State())
	gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Name().State())

	nextState := gnmi.Get(t, dut, counters.State())
	if errors := verifyInCounters(nextState); len(errors) != 0 {
		t.Fatalf("MGMT component (%v) has invalid next input counters: %v", bond0Name, errors)
	}

	t.Logf("Next in-counters state has:")
	t.Logf("  in-discards:%v  in-errors:%v  in-octets:%v  in-pkts: %v", nextState.GetInDiscards(), nextState.GetInErrors(), nextState.GetInOctets(), nextState.GetInPkts())

	if initialState.GetInDiscards() > nextState.GetInDiscards() {
		t.Errorf("MGMT component (%v) has unexpected decrease in in-discards %v -> %v", bond0Name, initialState.GetInDiscards(), nextState.GetInDiscards())
	}
	if nextState.GetInDiscards() != 0 {
		t.Logf("MGMT component (%v) has non-zero in-discards: %v", bond0Name, nextState.GetInDiscards())
	}
	if initialState.GetInErrors() > nextState.GetInErrors() {
		t.Errorf("MGMT component (%v) has unexpected decrease in in-errors %v -> %v", bond0Name, initialState.GetInErrors(), nextState.GetInErrors())
	}
	if nextState.GetInErrors() != 0 {
		t.Logf("MGMT component (%v) has non-zero in-errors: %v", bond0Name, nextState.GetInErrors())
	}
	if initialState.GetInOctets() >= nextState.GetInOctets() {
		t.Errorf("MGMT component (%v) in-octets did not increase as expected %v -> %v", bond0Name, initialState.GetInOctets(), nextState.GetInOctets())
	}
	if initialState.GetInPkts() >= nextState.GetInPkts() {
		t.Errorf("MGMT component (%v) in-pkts did not increase as expected %v -> %v", bond0Name, initialState.GetInPkts(), nextState.GetInPkts())
	}
}

func TestOutCounters(t *testing.T) {
	// This test confirms that the output counters (TX side) are updated by packet
	// events.  Note: the management interface is the connection by which gNMI
	// operations take place, so it is difficult to get a precise count of the
	// expected differences in counter values.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/state/counters/out-discards
	//   /interfaces/interface[name=<mgmt>]/state/counters/out-errors
	//   /interfaces/interface[name=<mgmt>]/state/counters/out-octets
	//   /interfaces/interface[name=<mgmt>]/state/counters/out-pkts
	defer testhelper.NewTearDownOptions(t).WithID("ccec883e-0b87-4084-8861-77393460976b").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	counters := gnmi.OC().Interface(bond0Name).Counters()
	initialState := gnmi.Get(t, dut, counters.State())
	if errors := verifyOutCounters(initialState); len(errors) != 0 {
		t.Fatalf("MGMT component (%v) has invalid initial output counters: %v", bond0Name, errors)
	}

	t.Logf("Initial out-counters state has:")
	t.Logf("  out-discards:%v  out-errors:%v  out-octets:%v  out-pkts: %v", initialState.GetOutDiscards(), initialState.GetOutErrors(), initialState.GetOutOctets(), initialState.GetOutPkts())

	// The management interface is active.  That is how gNMI operations are
	// communicated to the switch.  In this test, we verify that packets have been
	// received and that there were no errors.
	// Initiate a handful of Get operations to ensure there is traffic.
	gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Name().State())
	gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Name().State())
	gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Name().State())

	nextState := gnmi.Get(t, dut, counters.State())
	if errors := verifyOutCounters(nextState); len(errors) != 0 {
		t.Fatalf("MGMT component (%v) has invalid next output counters: %v", bond0Name, errors)
	}

	t.Logf("Next out-counters state has:")
	t.Logf("  out-discards:%v  out-errors:%v  out-octets:%v  out-pkts: %v", nextState.GetOutDiscards(), nextState.GetOutErrors(), nextState.GetOutOctets(), nextState.GetOutPkts())

	if initialState.GetOutDiscards() > nextState.GetOutDiscards() {
		t.Errorf("MGMT component (%v) has unexpected decrease in out-discards %v -> %v", bond0Name, initialState.GetOutDiscards(), nextState.GetOutDiscards())
	}
	if nextState.GetOutDiscards() != 0 {
		t.Logf("MGMT component (%v) has non-zero out-discards: %v", bond0Name, nextState.GetOutDiscards())
	}
	if initialState.GetOutErrors() > nextState.GetOutErrors() {
		t.Errorf("MGMT component (%v) has unexpected decrease in out-errors %v -> %v", bond0Name, initialState.GetOutErrors(), nextState.GetOutErrors())
	}
	if nextState.GetOutErrors() != 0 {
		t.Logf("MGMT component (%v) has non-zero out-errors: %v", bond0Name, nextState.GetOutErrors())
	}
	if initialState.GetOutOctets() >= nextState.GetOutOctets() {
		t.Errorf("MGMT component (%v) out-octets did not increase as expected %v -> %v", bond0Name, initialState.GetOutOctets(), nextState.GetOutOctets())
	}
	if initialState.GetOutPkts() >= nextState.GetOutPkts() {
		t.Errorf("MGMT component (%v) out-pkts did not increase as expected %v -> %v", bond0Name, initialState.GetOutPkts(), nextState.GetOutPkts())
	}
}

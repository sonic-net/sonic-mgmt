package mgmt_interface_test

// This suite of tests exercises the gNMI paths associated with the management

import (
	"errors"
	"fmt"
	"math/rand"
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

// -----------------------------------------------------------------------------
// IPv4 path tests
// -----------------------------------------------------------------------------
func TestSetIPv4AddressAndPrefixLength(t *testing.T) {
	// This test confirms that a new IPv4 address and prefix-length can be added.
	// Note: the entire "tree" has to be added in one gNMI operation.  (The IP and
	// prefix length cannot be written separately.)
	// formed.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv4/addresses/address[ip=<address>]/config/ip
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv4/addresses/address[ip=<address>]/config/prefix-length
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv4/addresses/address[ip=<address>]/state/ip
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv4/addresses/address[ip=<address>]/state/prefix-length
	defer testhelper.NewTearDownOptions(t).WithID("64003075-93a5-41b3-b962-74e9f36dde94").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	// We can't change the management interface IP address; the connection via the
	// proxy would be lost.  We can, however, write the existing value again.
	newIPv4Info, err := fetchMgmtIPv4AddressAndPrefix(t)
	restoreIPv4State := false

	if err != nil {
		// If IPv4 is not used in the testbed, we can set a valid address.
		t.Logf("Unable to fetch IPv4 management address: %v", err)
		t.Logf("We will create an unused one.")
		// Address is [16:126].[0:255].[0:255].[0:255].
		start, end := 16, 126
		firstPrefixPart1 := make([]int, end-start+1)
		for i := range firstPrefixPart1 {
			firstPrefixPart1[i] = i + start
		}
		start, end = 128, 223
		firstPrefixPart2 := make([]int, end-start+1)
		for i := range firstPrefixPart2 {
			firstPrefixPart2[i] = i + start
		}
		firstPrefix := append(firstPrefixPart1, firstPrefixPart2...)

		newAddr := fmt.Sprintf("%d.%d.%d.%d", firstPrefix[rand.Int()%len(firstPrefix)], rand.Intn(256), rand.Intn(256), rand.Intn(256))
		newPrefix := uint8(rand.Intn(27) + 5) // 5 to 31
		newIPv4Info = ipAddressInfo{address: newAddr, prefixLength: newPrefix}
		restoreIPv4State = true
	}

	d := &oc.Root{}
	iface := d.GetOrCreateInterface(bond0Name).GetOrCreateSubinterface(interfaceIndex)
	newV4 := iface.GetOrCreateIpv4().GetOrCreateAddress(newIPv4Info.address)
	newV4.Ip = &newIPv4Info.address
	newV4.PrefixLength = &newIPv4Info.prefixLength

	ipv4 := gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv4().Address(newIPv4Info.address)
	gnmi.Replace(t, dut, gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv4().Address(newIPv4Info.address).Config(), newV4)
	if restoreIPv4State {
		defer gnmi.Delete(t, dut, gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv4().Address(newIPv4Info.address).Config())
	}
	// Give the configuration a chance to become active.
	time.Sleep(1 * time.Second)

	if observed := gnmi.Get(t, dut, ipv4.State()); observed.GetIp() != newIPv4Info.address || observed.GetPrefixLength() != newIPv4Info.prefixLength {
		t.Errorf("MGMT component (%v) address match failed! state-path-value:%v/%v (want:%v/%v)", bond0Name, observed.GetIp(), observed.GetPrefixLength(), newIPv4Info.address, newIPv4Info.prefixLength)
	}
}

func TestSetIPv4InvalidAddress(t *testing.T) {
	// This test confirms that an invalid IPv4 address cannot be set.
	// IPv4 addresses that begin with 0 or 255 (e.g. 255.1.2.3 or 0.4.5.6) are
	// considered invalid.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv4/addresses/address[ip=<address>]/config/ip
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv4/addresses/address[ip=<address>]/state/ip
	defer testhelper.NewTearDownOptions(t).WithID("00acbce9-069e-43e1-a511-9b45bb3ad5b0").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	var invalidIPPaths = []string{
		fmt.Sprintf("255.%v.%v.%v", rand.Intn(256), rand.Intn(256), rand.Intn(256)),
		fmt.Sprintf("0.%v.%v.%v", rand.Intn(256), rand.Intn(256), rand.Intn(256)),
	}
	configuredIPv4PrefixLength := uint8(16)

	for _, invalidIPPath := range invalidIPPaths {

		d := &oc.Root{}
		iface := d.GetOrCreateInterface(bond0Name).GetOrCreateSubinterface(interfaceIndex)
		newV4 := iface.GetOrCreateIpv4().GetOrCreateAddress(invalidIPPath)
		newV4.Ip = &invalidIPPath
		newV4.PrefixLength = &configuredIPv4PrefixLength

		ipv4 := gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv4().Address(invalidIPPath)
		ipv4Config := gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv4().Address(invalidIPPath)
		// Cannot write invalid IPv4 address.
		testt.ExpectFatal(t, func(t testing.TB) {
			gnmi.Replace(t, dut, ipv4Config.Config(), newV4)
		})

		// There should be no IP set with the invalid IPv4 address.
		testt.ExpectFatal(t, func(t testing.TB) {
			observedIP := gnmi.Get(t, dut, ipv4.Ip().State())
			t.Logf("MGMT component (%v) observed IPv4 address: %v.", bond0Name, observedIP)
		})
	}
}

// -----------------------------------------------------------------------------
// IPv6 path tests
// -----------------------------------------------------------------------------
func TestGetIPv6DefaultInfo(t *testing.T) {
	// This test confirms that generic IPv6 information can be read and is well
	// formed.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/state/ip
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/state/prefix-length
	defer testhelper.NewTearDownOptions(t).WithID("5bc725a2-befe-4154-bd7d-d390c87dc4d8").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	configuredIPv6Info, err := fetchMgmtIPv6AddressAndPrefix(t)
	if err != nil {
		t.Fatalf("Unable to fetch IPv6 management address: %v", err)
	}
	ipv6 := gnmi.Get(t, dut, gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv6().Address(configuredIPv6Info.address).State())

	if *ipv6.PrefixLength >= 128 {
		t.Errorf("MGMT component (%v) has an incorrect prefix-length: %v (want: [0:127]) on subinterface %v with IP %v", bond0Name, *ipv6.PrefixLength, interfaceIndex, configuredIPv6Info.address)
	}
	parsedIP := net.ParseIP(*ipv6.Ip)
	if parsedIP == nil {
		t.Fatalf("MGMT component (%v) has an incorrectly formatted IPv6 address: %v", bond0Name, *ipv6.Ip)
	}
	ipAsBytes := parsedIP.To16()
	if ipAsBytes == nil {
		t.Fatalf("MGMT component (%v) has an incorrectly formatted IPv6 address: %v could not be parsed", bond0Name, *ipv6.Ip)
	}
	if len(ipAsBytes) != 16 {
		t.Fatalf("MGMT component (%v) IPv6 address is only %v bytes.", bond0Name, len(ipAsBytes))
	}
}

func TestSetIPv6AddressAndPrefixLength(t *testing.T) {
	// This test confirms that a new IPv6 address and prefix-length can be added.
	// Note: the entire "tree" has to be added in one gNMI operation.  (The IP and
	// prefix length cannot be written separately.)
	// formed.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/config/ip
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/config/prefix-length
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/state/ip
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/state/prefix-length
	defer testhelper.NewTearDownOptions(t).WithID("0f79f318-b0de-4352-a045-540aa1da94d4").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	// We can't change the management interface IP address; the connection via the
	// proxy would be lost.  We can, however, write the existing value again.
	newIPInfo, err := fetchMgmtIPv6AddressAndPrefix(t)
	if err != nil {
		t.Fatalf("Unable to fetch IPv6 management address: %v", err)
	}

	d := &oc.Root{}
	iface := d.GetOrCreateInterface(bond0Name).GetOrCreateSubinterface(interfaceIndex)
	newV6 := iface.GetOrCreateIpv6().GetOrCreateAddress(newIPInfo.address)
	newV6.Ip = &newIPInfo.address
	newV6.PrefixLength = &newIPInfo.prefixLength

	ipv6 := gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv6().Address(newIPInfo.address)
	gnmi.Replace(t, dut, gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv6().Address(newIPInfo.address).Config(), newV6)
	// Give the configuration a chance to become active.
	time.Sleep(1 * time.Second)

	if observed := gnmi.Get(t, dut, ipv6.State()); *observed.Ip != newIPInfo.address || *observed.PrefixLength != newIPInfo.prefixLength {
		t.Errorf("MGMT component (%v) address match failed! state-path-value:%v/%v (want:%v/%v)", bond0Name, *observed.Ip, *observed.PrefixLength, newIPInfo.address, newIPInfo.prefixLength)
	}
}

func TestSetIPv6InvalidPrefixLength(t *testing.T) {
	// This test confirms that an invalid IPv6 prefix-length cannot be set.
	// Any prefix length in the range [0:128] is supported.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/config/prefix-length
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/state/prefix-length
	defer testhelper.NewTearDownOptions(t).WithID("7813ab28-1d8c-43ca-ab21-d4106a733e47").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	configuredIPv6Info, err := fetchMgmtIPv6AddressAndPrefix(t)
	if err != nil {
		t.Fatalf("Unable to fetch IPv6 management address: %v", err)
	}
	ipv6 := gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv6().Address(configuredIPv6Info.address)
	ipv6Config := gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv6().Address(configuredIPv6Info.address)
	originalPrefixLength := gnmi.Get(t, dut, ipv6.PrefixLength().State())

	invalidPrefixLength := uint8(129)
	testt.ExpectFatal(t, func(t testing.TB) {
		gnmi.Replace(t, dut, ipv6Config.PrefixLength().Config(), invalidPrefixLength)
	})
	gnmi.Await(t, dut, ipv6.PrefixLength().State(), 5*time.Second, originalPrefixLength)
	configuredPrefixLength := gnmi.Get(t, dut, ipv6Config.PrefixLength().Config())

	if configuredPrefixLength == invalidPrefixLength {
		t.Errorf("MGMT component (%v) prefix-length match failed! set:%v, config-path-value:%v (want:%v)", bond0Name, invalidPrefixLength, configuredPrefixLength, originalPrefixLength)
	}
}

func TestSetIPv6InvalidAddress(t *testing.T) {
	// This test confirms that an invalid IPv6 address cannot be set.
	// Paths tested:
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/config/ip
	//   /interfaces/interface[name=<mgmt>]/subinterfaces/subinterface[index=<index>]/ipv6/addresses/address[ip=<address>]/state/ip
	defer testhelper.NewTearDownOptions(t).WithID("c58360a6-4d7f-442d-a9f7-9f1d72682ee2").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	mockConfigPush(t)

	invalidIPPath := "ffff:ffff:ffff:ffff:ffff:f25c:77ff:fe7f:69be"
	configuredIPv6PrefixLength := uint8(64)
	ipv6 := gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv6().Address(invalidIPPath)
	ipv6Config := gnmi.OC().Interface(bond0Name).Subinterface(interfaceIndex).Ipv6().Address(invalidIPPath)

	d := &oc.Root{}
	iface := d.GetOrCreateInterface(bond0Name).GetOrCreateSubinterface(interfaceIndex)
	newV6 := iface.GetOrCreateIpv6().GetOrCreateAddress(invalidIPPath)
	newV6.Ip = &invalidIPPath
	newV6.PrefixLength = &configuredIPv6PrefixLength

	// Cannot write invalid IPv6 address.
	testt.ExpectFatal(t, func(t testing.TB) {
		gnmi.Replace(t, dut, ipv6Config.Config(), newV6)
	})

	// There should be no IP set with the invalid IPv6 address.
	testt.ExpectFatal(t, func(t testing.TB) {
		observedIP := gnmi.Get(t, dut, ipv6.Ip().State())
		t.Logf("MGMT component (%v) observed IPv6 address: %v.", bond0Name, observedIP)
	})
}

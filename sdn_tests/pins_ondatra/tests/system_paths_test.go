package system_paths_test

import (
        "strings"
        "testing"
        "time"

        "github.com/openconfig/ondatra"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
        "github.com/pkg/errors"

        "github.com/openconfig/ondatra/gnmi"
)

func TestMain(m *testing.M) {
        ondatra.RunTests(m, pinsbind.New)
}

func verifyAddress(address string, addresses []string) error {
        for _, addr := range addresses {
                if addr == address {
                        return nil
                }
        }
        return errors.New("unknown address")
}

func TestGetRemoteServerAddressInfo(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("c2873412-1016-4c89-9e59-79fcfec642bb").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        logInfo, err := testhelper.LoggingServerAddressesForDevice(t, dut)
        if err != nil {
                t.Fatalf("Failed to fetch remote server logging info: %v", err)
        }

        // Collect remote server addresses.
        foundAddresses := gnmi.GetAll(t, dut, gnmi.OC().System().Logging().RemoteServerAny().Host().State())

        // Determine if configured addresses are IPv4 or IPv6.  We are only allowed to have one or the other.
        hasIpv4, hasIpv6 := false, false
        for _, addr := range foundAddresses {
                if err := verifyAddress(addr, logInfo.IPv4RemoteAddresses); err == nil {
                        hasIpv4 = true
                }
                if err := verifyAddress(addr, logInfo.IPv6RemoteAddresses); err == nil {
                        hasIpv6 = true
                }
        }

        if !hasIpv4 && !hasIpv6 {
                t.Fatalf("Remote server addresses do not match device logging server addresses: got: %v vs want: %v or want: %v ", strings.Join(foundAddresses, ", "), strings.Join(logInfo.IPv4RemoteAddresses, ", "), strings.Join(logInfo.IPv6RemoteAddresses, ", "))
        }
        if hasIpv4 && hasIpv6 {
                t.Fatalf("Remote server addresses are not expected to mix IPv4 and IPv6 addresses: got: %v", strings.Join(foundAddresses, ", "))
        }

        addresses := logInfo.IPv4RemoteAddresses
        if hasIpv6 {
                addresses = logInfo.IPv6RemoteAddresses
        }

        // Addresses configured may only be what device configuration allows.
        if foundLen, addressLen := len(foundAddresses), len(addresses); foundLen != addressLen {
                t.Errorf("Unexpected number of remote logging server addresses: %v (want %v).", foundLen, addressLen)
        }

        addressSet := make(map[string]bool)
        for _, addr := range foundAddresses {
                addressSet[addr] = true
        }
        // Addresses may not be repeated.
        if setLen, foundLen := len(addressSet), len(foundAddresses); setLen != foundLen {
                t.Errorf("Remote logging addresses are not unique: %v", foundAddresses)
        }

        // Addresses configured may only be what device configuration allows.
        for _, addr := range foundAddresses {
                if err := verifyAddress(addr, addresses); err != nil {
                        t.Errorf("Remote logging address is unsupported: %v", addr)
                }
        }

        // Check that state host value matches the rest of the path.
        for _, addr := range foundAddresses {
                if readAddress := gnmi.Get(t, dut, gnmi.OC().System().Logging().RemoteServer(addr).Host().State()); readAddress != addr {
                        t.Errorf("Remote logging host address does not match path: %v vs %v", readAddress, addr)
                }
        }
}

func TestGetCurrentDateAndTime(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID("8ec03425-b9ab-4e13-8b01-1564b5043d68").Teardown(t)
        dut := ondatra.DUT(t, "DUT")

        t1 := time.Now()
        time.Sleep(1 * time.Second)
        dutTime, err := time.Parse(time.RFC3339, gnmi.Get(t, dut, gnmi.OC().System().CurrentDatetime().State()))
        if err != nil {
                t.Fatalf("Failed to parse DUT time: %v", err)
        }
        t2 := time.Now()

        // Time reported by DUT should be between the time the request was sent and received.
        if dutTime.Before(t1) || dutTime.After(t2) {
                t.Errorf("Time comparison failed! got:%v, want:(greater than:%v, less than:%v)", dutTime, t1, t2)
        }
}

package gnmi_subscribe_modes_test

import (
        "context"
        "errors"
        "fmt"
        "strings"
        "testing"
        "time"

        "github.com/google/go-cmp/cmp"
        "github.com/google/go-cmp/cmp/cmpopts"
        gpb "github.com/openconfig/gnmi/proto/gnmi"
        "github.com/openconfig/ondatra"
        "github.com/openconfig/ondatra/gnmi"
        "github.com/openconfig/ygot/ygot"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
        "google.golang.org/grpc"
        "google.golang.org/protobuf/encoding/prototext"
)

const (
        deleteTreePath = "/system/config/"
        deletePath     = "/system/config/hostname"
        timePath       = "/system/state/current-datetime"
        nodePath       = "/system/state/hostname"
        subTreePath    = "/system/state"
        containerPath  = "/components"
        rootPath       = "/"
        onChangePath   = "/interfaces/interface[name=%s]/state/mtu"
        errorResponse  = "expectedError"
        syncResponse   = "expectedSync"

        shortTime  = 5 * time.Second
        mediumTime = 10 * time.Second
        longTime   = 30 * time.Second
)

func TestMain(m *testing.M) {
        ondatra.RunTests(m, pinsbind.New)
}

type subscribeTest struct {
        uuid              string
        reqPath           string
        mode              gpb.SubscriptionList_Mode
        updatesOnly       bool
        subMode           gpb.SubscriptionMode
        sampleInterval    uint64 // nanoseconds
        suppressRedundant bool
        heartbeatInterval uint64 // nanoseconds
        expectError       bool
        timeout           time.Duration
}

type operStatus struct {
        match  bool
        delete bool
        value  string
}

func ignorePaths(path string) bool {
        // Paths that change during root and container level tests
        subPaths := []string{
                // TODO Check back if lb/bond are needed after this bug is corrected.
                "/ethernet/state/counters/",
                "//interfaces/interface[name=Loopback0]",
                "//interfaces/interface[name=bond0]",
                "//qos/interfaces/interface",
                "//snmp/engine/version/",
                "//system/mount-points/mount-point",
                "//system/processes/process",
                "//system/cpus/cpu",
                "//system/crm/threshold",
                "//system/ntp/",
                "//system/memory/",
                "//system/ssh-server/ssh-server-vrfs",
                "/subinterface[index=0]/ipv4/unnumbered/",
                "/subinterface[index=0]/ipv4/sag-ipv4/",
                "/subinterface[index=0]/ipv6/sag-ipv6/",
                "/gnmi-pathz-policy-counters/paths/path",
                "/system/state/boot-time",
                "/system/state/uptime",
        }

        for _, sub := range subPaths {
                if strings.Contains(path, sub) {
                        return true
                }
        }
        return false
}

var skipTest = map[string]bool{
        // TODO Ondatra fails to delete subtree
        "TestGNMISubscribeModes/subscribeDeleteNodeLevel":    true,
        "TestGNMISubscribeModes/subscribeDeleteSubtreeLevel": true,
}

// Test for gNMI Subscribe Stream mode for OnChange subscriptions.
func (c subscribeTest) subModeOnChangeTest(t *testing.T) {
        defer testhelper.NewTearDownOptions(t).WithID(c.uuid).Teardown(t)
        if skipTest[t.Name()] {
                t.Skip()
        }
        dut := ondatra.DUT(t, "DUT")

        var intf string
        if c.expectError == false {
                var err error
                intf, err = testhelper.RandomInterface(t, dut, nil)
                if err != nil {
                        t.Fatalf("Failed to fetch random interface: %v", err)
                }
                c.reqPath = fmt.Sprintf(c.reqPath, intf)
        }
        subscribeRequest := buildRequest(t, c, dut.Name())
        t.Logf("SubscribeRequest:\n%v", prototext.Format(subscribeRequest))

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()
        gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
        if err != nil {
                t.Fatalf("Unable to get gNMI client (%v)", err)
        }
        subscribeClient, err := gnmiClient.Subscribe(ctx)
        if err != nil {
                t.Fatalf("Unable to get subscribe client (%v)", err)
        }

        if err := subscribeClient.Send(subscribeRequest); err != nil {
                t.Fatalf("Failed to send gNMI subscribe request (%v)", err)
        }

        expectedPaths := make(map[string]operStatus)
        if !c.updatesOnly {
                expectedPaths = c.buildExpectedPaths(t, dut)
        }
        expectedPaths[syncResponse] = operStatus{}

        foundPaths, _ := collectResponse(t, subscribeClient, expectedPaths)
        if c.expectError {
                foundErr, ok := foundPaths[errorResponse]
                if !ok {
                        t.Fatal("Expected error but got none")
                }
                if !strings.Contains(foundErr.value, "InvalidArgument") {
                        t.Errorf("Error is not an InvalidArgument: %s", foundErr.value)
                }
                return
        }
        if diff := cmp.Diff(expectedPaths, foundPaths, cmpopts.IgnoreUnexported(operStatus{})); diff != "" {
                t.Errorf("collectResponse(expectedPaths):\n%v \nResponse mismatch (-missing +extra):\n%s", expectedPaths, diff)
        }
        delete(expectedPaths, syncResponse)

        got := gnmi.Get(t, dut, gnmi.OC().Interface(intf).Mtu().State())
        defer gnmi.Update(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), got)
        mtu := uint16(1500)
        if got == 1500 {
                mtu = 9000
        }
        if c.heartbeatInterval == 0 {
                gnmi.Update(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), mtu)
        }

        foundPaths, delay := collectResponse(t, subscribeClient, expectedPaths)
        if diff := cmp.Diff(expectedPaths, foundPaths, cmpopts.IgnoreUnexported(operStatus{})); diff != "" {
                t.Errorf("collectResponse(expectedPaths):\n%v \nResponse mismatch (-missing +extra):\n%s", expectedPaths, diff)
        }
        if c.heartbeatInterval != 0 {
                if delay > time.Duration(c.heartbeatInterval+(c.heartbeatInterval/2)) {
                        t.Errorf("Failed sampleInterval with time of %v", delay)
                }
                gnmi.Update(t, dut, gnmi.OC().Interface(intf).Mtu().Config(), mtu)
                foundPaths, _ := collectResponse(t, subscribeClient, expectedPaths)
                if diff := cmp.Diff(expectedPaths, foundPaths, cmpopts.IgnoreUnexported(operStatus{})); diff != "" {
                        t.Errorf("collectResponse(expectedPaths):\n%v \nResponse mismatch (-missing +extra):\n%s", expectedPaths, diff)
                }
        }
}

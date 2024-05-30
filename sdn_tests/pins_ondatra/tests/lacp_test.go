package lacp_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
        "github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"github.com/pkg/errors"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
)

// gNMI can cache local state for up to 10 seconds. We therefore set our timeout to a little longer
// to handle any edge cases when verifying state.
const defaultGNMIWait = 15 * time.Second

// IEEE 802.3ad defines the Link Aggregation standard used by LACP where connected ports can
// exchange control packets between each other. Based on these packets the switch can group matching
// ports into a LAG/Trunk/PortChannel.
//
// Local state is maintained for each member of a LAG to monitor the health of that given member.
type lacpMemberState struct {
	activity        oc.E_Lacp_LacpActivityType
	timeout         oc.E_Lacp_LacpTimeoutType
	aggregatable    bool
	synchronization oc.E_Lacp_LacpSynchronizationType
	collecting      bool
	distributing    bool
}

// Wait for the switch state of a specific PortChannel member to converge to a users expectations.
// If the switch state does not converge return a string detailing the difference between the final
// state received, and what the user wanted.
func compareLacpMemberState(t *testing.T, dut *ondatra.DUTDevice, pcName string, memberName string, want lacpMemberState) string {
	t.Helper()

	// Wait for the switch value to match our expectation.
	predicate := func(val *ygnmi.Value[*oc.Lacp_Interface_Member]) bool {
		currentVal, present := val.Val()
		if !present {
			return false
		}
		return currentVal.GetActivity() == want.activity &&
			currentVal.GetTimeout() == want.timeout &&
			currentVal.GetAggregatable() == want.aggregatable &&
			currentVal.GetSynchronization() == want.synchronization &&
			currentVal.GetCollecting() == want.collecting &&
			currentVal.GetDistributing() == want.distributing
	}
	lastVal, match := gnmi.Watch(t, dut, gnmi.OC().Lacp().Interface(pcName).Member(memberName).State(), defaultGNMIWait, predicate).Await(t)

	state, ok := lastVal.Val()
	if !ok {
		return "no value for lacp interface member"
	}
	var diff strings.Builder
	if !match {
		fmt.Fprintf(&diff, "%v:%v:%v (-want, +got)", dut.Name(), pcName, memberName)

		if state.Activity == want.activity {
			fmt.Fprintf(&diff, "\nactivity:        %v", state.Activity)
		} else if state.Activity == oc.Lacp_LacpActivityType_UNSET {
			fmt.Fprintf(&diff, "\nactivity:        -%v, +(unset)", want.activity)
		} else {
			fmt.Fprintf(&diff, "\nactivity:        -%v, +%v", want.activity, state.Activity)
		}

		if state.Timeout == want.timeout {
			fmt.Fprintf(&diff, "\ntimeout:         %v", state.Timeout)
		} else if state.Timeout == oc.Lacp_LacpTimeoutType_UNSET {
			fmt.Fprintf(&diff, "\ntimeout:         -%v, +(unset)", want.timeout)
		} else {
			fmt.Fprintf(&diff, "\ntimeout:         -%v, +%v", want.timeout, state.Timeout)
		}

		if state.Aggregatable != nil && *state.Aggregatable == want.aggregatable {
			fmt.Fprintf(&diff, "\naggregatable:    %v", *state.Aggregatable)
		} else if state.Aggregatable == nil {
			fmt.Fprintf(&diff, "\naggregatable:    -%v, +(unset)", want.aggregatable)
		} else {
			fmt.Fprintf(&diff, "\naggregatable:    -%v, +%v", want.aggregatable, *state.Aggregatable)
		}

		if state.Synchronization == want.synchronization {
			fmt.Fprintf(&diff, "\nsynchronization: %v", state.Synchronization)
		} else if state.Synchronization == oc.Lacp_LacpSynchronizationType_UNSET {
			fmt.Fprintf(&diff, "\nsynchronization: -%v, +(unset)", want.synchronization)
		} else {
			fmt.Fprintf(&diff, "\nsynchronization: -%v, +%v", want.synchronization, state.Synchronization)
		}

		if state.Collecting != nil && *state.Collecting == want.collecting {
			fmt.Fprintf(&diff, "\ncollecting:      %v", state.Collecting)
		} else if state.Collecting == nil {
			fmt.Fprintf(&diff, "\ncollecting:      -%v, +(unset)", want.collecting)
		} else {
			fmt.Fprintf(&diff, "\ncollecting:      -%v, -%v", want.collecting, *state.Collecting)
		}

		if state.Distributing != nil && *state.Distributing == want.distributing {
			fmt.Fprintf(&diff, "\ndistributing:    %v", *state.Distributing)
		} else if state.Distributing == nil {
			fmt.Fprintf(&diff, "\ndistributing:    -%v, +(unset)", want.distributing)
		} else {
			fmt.Fprintf(&diff, "\ndistributing:    -%v, +%v", want.distributing, *state.Distributing)
		}
	}
	return diff.String()
}

// Blocking state happens when one side of the LACP connection is up, but the other is not. For
// example, a port is down, or not yet configured. When this happens we expect the member to still
// be active and aggregatable (i.e. waiting for the other end to come up), but not yet in-sync or
// collecting/distributing traffic.
func verifyBlockingState(t *testing.T, dut *ondatra.DUTDevice, pcName string, memberName string) error {
	t.Helper()

	want := lacpMemberState{
		activity:        oc.Lacp_LacpActivityType_ACTIVE,
		timeout:         oc.Lacp_LacpTimeoutType_LONG,
		aggregatable:    true,
		synchronization: oc.Lacp_LacpSynchronizationType_OUT_SYNC,
		collecting:      false,
		distributing:    false,
	}

	// gNMI does not support ON_CHANGE events for LACP paths, and SAMPLING can fatally fail if an
	// entry doesn't yet exist (i.e. we call this too quickly after sending a config). So to prevent
	// flakes we run this check twice in a row.
	if firstDiff := compareLacpMemberState(t, dut, pcName, memberName, want); firstDiff != "" {
		log.Warningf("Failed first blocking check: %s", firstDiff)
		if secondDiff := compareLacpMemberState(t, dut, pcName, memberName, want); secondDiff != "" {
			return errors.New(secondDiff)
		}
	}
	return nil
}

// In-Sync state happens when both side of the LACP connection are up and healthy. When in this
// state we expect the member to be active, aggregatable, in-sync, collecting, and distributing
// traffic.
func verifyInSyncState(t *testing.T, dut *ondatra.DUTDevice, pcName string, memberName string) error {
	t.Helper()

	want := lacpMemberState{
		activity:        oc.Lacp_LacpActivityType_ACTIVE,
		timeout:         oc.Lacp_LacpTimeoutType_LONG,
		aggregatable:    true,
		synchronization: oc.Lacp_LacpSynchronizationType_IN_SYNC,
		collecting:      true,
		distributing:    true,
	}

	// gNMI does not support ON_CHANGE events for LACP paths, and SAMPLING can fatally fail if an
	// entry doesn't yet exist (i.e. we call this too quickly after sending a config). So to prevent
	// flakes we run this check twice in a row.
	if firstDiff := compareLacpMemberState(t, dut, pcName, memberName, want); firstDiff != "" {
		log.Warningf("Failed first in-sync check: %s", firstDiff)
		if secondDiff := compareLacpMemberState(t, dut, pcName, memberName, want); secondDiff != "" {
			return errors.New(secondDiff)
		}
	}
	return nil
}

// gNMI does not specify an ordering for the member list of a PortChannel. To make tests
// reproducible we need to sort the member lists before comparing.
func comparePortChannelMemberList(t *testing.T, timeout time.Duration, dut *ondatra.DUTDevice, pcName string, members []string) error {
	t.Helper()

	// Users do not have to pre-sort their list.
	sort.Strings(members)

	predicate := func(val *ygnmi.Value[[]string]) bool {
		got, present := val.Val()
		// If the value isn't present then simply return false.
		if !present {
			return false
		}

		// Otherwise, sort the values from the switch, and compare them to the expectations.
		sort.Strings(got)
		return cmp.Equal(members, got)
	}

	// gNMI does not support ON_CHANGE events for LACP paths, and SAMPLING can fatally fail if an
	// entry doesn't yet exist (i.e. we call this too quickly after sending a config). So to prevent
	// flakes we run this check twice in a row.
	if lastVal, matched := gnmi.Watch(t, dut, gnmi.OC().Interface(pcName).Aggregation().Member().State(), timeout, predicate).Await(t); !matched {
		log.Warningf("Failed first membership check: %v", lastVal)
		if lastVal, again := gnmi.Watch(t, dut, gnmi.OC().Interface(pcName).Aggregation().Member().State(), timeout, predicate).Await(t); !again {
			return errors.Errorf("member state does not match %v:%v", members, lastVal)
		}
	}
	return nil
}

// Translates an openconfig ETHERNET_SPEED into Mbps which can be used to verify a LAG's speed.
func ethernetPortSpeedToMbps(speed oc.E_IfEthernet_ETHERNET_SPEED) (uint32, error) {
	// Returns bits/sec.
	bps, err := testhelper.EthernetSpeedToUint64(speed)
	if err != nil {
		return 0, err
	}
	return uint32(bps / 1_000_000), nil
}

// Fetches the configured PortSpeed for a list of ports, and aggregates the values together. Can be
// be used to verify a PortChannel speed matches the total of all its member ports.
func aggregatedPortSpeed(t *testing.T, dut *ondatra.DUTDevice, ports []string) (uint32, error) {
	lagSpeed := uint32(0)

	for _, port := range ports {
		portSpeed, err := ethernetPortSpeedToMbps(gnmi.Get(t, dut, gnmi.OC().Interface(port).Ethernet().PortSpeed().Config()))
		if err != nil {
			return 0, errors.Wrapf(err, "could not get port speed for %s", port)
		}
		lagSpeed += portSpeed
	}

	return lagSpeed, nil
}

// Used by go/ondatra to automatically reserve an available testbed.
func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

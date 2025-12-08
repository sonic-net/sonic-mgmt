package testhelper

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/grpc"
)

const (
	configConvergenceTimeout      = 2 * time.Minute
	configConvergencePollInterval = 30 * time.Second
	switchStateTimeout            = 2 * time.Minute
	switchStatePollInterval       = 10 * time.Second
	portsUpTimeout                = 2 * time.Minute
)

// configStateDiffReporter is a custom diff reporter for comparing
// config and state. It ignores the diffs that are not relevant
// for comparing config and state.
type configStateDiffReporter struct {
	path  cmp.Path
	diffs []string
}

func (r *configStateDiffReporter) PushStep(ps cmp.PathStep) {
	r.path = append(r.path, ps)
}

func (r *configStateDiffReporter) PopStep() {
	r.path = r.path[:len(r.path)-1]
}

func (r *configStateDiffReporter) String() string {
	return strings.Join(r.diffs, "\n")
}

func (r *configStateDiffReporter) isValueNil(v *reflect.Value) bool {
	// Check if the type can be nil.
	if v.Kind() == reflect.Ptr ||
		v.Kind() == reflect.Interface ||
		v.Kind() == reflect.Slice ||
		v.Kind() == reflect.Map {
		return v.IsNil()
	}
	return false
}

// isOCEnum checks if the value is an OpenConfig enum.
func (r *configStateDiffReporter) isOCEnum(v *reflect.Value) bool {
	t := strings.TrimPrefix(v.Type().String(), "oc.")
	_, ok := oc.ΛEnum[t]
	return ok
}

func (r *configStateDiffReporter) ignoreUnsupportedFields(confLeaf, stateLeaf *reflect.Value) bool {
	s := r.path.String()
	if strings.HasPrefix(s, "Sampling") {
		return true
	}
	if strings.HasPrefix(s, "Qos") {
		return true
	}
	if strings.HasPrefix(s, "System") {
		return true
	}
	return false
}

// Filter out the diffs that are not relevant for comparing config and state.
func (r *configStateDiffReporter) Report(rs cmp.Result) {
	if rs.Equal() {
		return
	}

	configLeaf, stateLeaf := r.path.Last().Values()
	if !configLeaf.IsValid() || !stateLeaf.IsValid() {
		return
	}

	// Do not report diff for nil config values.
	// A value is nil if the field doesn't exist in the JSON.
	// Since the config JSON doesn't has all the fields,
	// the diff can be ignored.
	if r.isValueNil(&configLeaf) {
		return
	}

	if r.ignoreUnsupportedFields(&configLeaf, &stateLeaf) {
		return
	}

	// In the OC structs, except the enum fields, others are represented as a pointer.
	// If a field is not present in the JSON, the value is nil,
	// but for the enums, if a field is not present,
	// the value is set to 0.
	// Ignore the diff if the enum value is set to 0.
	// Both leafs are expected to be of the same type always.
	if r.isOCEnum(&configLeaf) && r.isOCEnum(&stateLeaf) {
		if configLeaf.Int() == 0 || stateLeaf.Int() == 0 {
			return
		}
	}

	// Append the diff to the list of diffs.
	r.diffs = append(r.diffs, fmt.Sprintf("%#v:\n\t-: %+v\n\t+: %+v\n", r.path, configLeaf, stateLeaf))
}

// switchStateAsOCRoot returns the switch state as a go struct.
func switchStateAsOCRoot(ctx context.Context, dut *ondatra.DUTDevice) (*oc.Root, error) {
	getReq := &gpb.GetRequest{
		Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
		Path:     []*gpb.Path{},
		Type:     gpb.GetRequest_ALL,
		Encoding: gpb.Encoding_JSON_IETF,
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// Fetch raw gNMI client and call Set API to send Get Request.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("unable to get gNMI client (%v)", err)
	}

	getResp, err := gnmiClient.Get(ctx, getReq)
	if err != nil {
		return nil, fmt.Errorf("gnmiClient.Get(getReq=%v) failed : %v", getReq, err)
	}

	return UnmarshalStateNotificationsToOCRoot(getResp.GetNotification())
}

// CompareConfigAndStateValues compares the config and state values
// and returns the diff if any.
// If provided, the config should be in JSON RFC7951 format.
func CompareConfigAndStateValues(ctx context.Context, t *testing.T, dut *ondatra.DUTDevice, config []byte) (string, error) {
	if dut == nil {
		return "", errors.New("nil DUT passed to CompareConfigAndStateValues()")
	}
	dutName := dut.Name()
	log.InfoContextf(ctx, "comparing config and state for dut: %v", dutName)
	configRoot := &oc.Root{}
	if err := oc.Unmarshal(config,
		configRoot,
		&ytypes.IgnoreExtraFields{},
		&ytypes.PreferShadowPath{}); err != nil {
		return "", fmt.Errorf("oc.Unmarshal() failed for config: %v", err)
	}

	stateRoot, err := switchStateAsOCRoot(ctx, dut)
	if err != nil {
		return "", fmt.Errorf("fetching switchStateAsOCRoot(dut=%v) failed with err: %v", dutName, err)
	}

	var r configStateDiffReporter
	cmp.Diff(configRoot, stateRoot, cmp.Reporter(&r))
	return r.String(), nil
}

// pollFunc returns true if the condition is met.
type pollFunc func() bool

// poll polls the condition until it is met or the context is done.
func poll(ctx context.Context, t *testing.T, interval time.Duration, pf pollFunc) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("polling for condition failed, err: %v", ctx.Err())
		case <-ticker.C:
			if pf() {
				log.InfoContextf(ctx, "polling done")
				return nil
			}
		}
	}
}

// WaitForConfigConvergence checks for differences between config and state.
// Polls till configConvergenceTimeout,
// returns error if the difference still exists.
func WaitForConfigConvergence(ctx context.Context, t *testing.T, dut *ondatra.DUTDevice, config []byte) error {
	if dut == nil {
		return errors.New("nil DUT passed to WaitForConfigConvergence()")
	}
	if config == nil {
		return errors.New("nil config passed to WaitForConfigConvergence()")
	}
	ctx, cancel := context.WithTimeout(ctx, configConvergenceTimeout)
	defer cancel()
	dutName := dut.Name()
	// Poll until the config and state are similar.
	return poll(ctx, t, configConvergencePollInterval, func() bool {
		diff, err := CompareConfigAndStateValues(ctx, t, dut, config)
		if err != nil {
			log.InfoContextf(ctx, "Comparing config and state failed for dut: %v, err: %v", dutName, err)
			return false
		}
		if diff == "" {
			log.InfoContextf(ctx, "Config and state converged for dut: %v", dutName)
			return true
		}
		log.InfoContextf(ctx, "diff in config and state found for dut: %v\ndiff_begin:\n%v\ndiff_end\n", dutName, diff)
		return false
	})
}

// ConfigPushAndWaitForConvergence pushes the config to the dut
// and waits for the config to converge.
// If config is nil, the config is fetched.
func ConfigPushAndWaitForConvergence(ctx context.Context, t *testing.T, dut *ondatra.DUTDevice, config []byte) error {
	if dut == nil {
		return errors.New("nil DUT passed to ConfigPushAndVerifyConvergence()")
	}
	dutName := dut.Name()
	// If config is nil, fetch the config from the switch.
	if config == nil {
		var err error
		config, err = GNMIConfigDUT{DUT: dut}.ConfigGet(t)
		if err != nil {
			return fmt.Errorf("ConfigGet(dut=%v) failed, err: %v", dutName, err)
		}
	}
	if err := ConfigPush(t, dut, config); err != nil {
		return fmt.Errorf("ConfigPush(dut=%v) failed, err: %v", dutName, err)
	}
	return WaitForConfigConvergence(ctx, t, dut, config)
}

// inEthernetPortChannelLaneFormat checks if the interface name is in the format
// of EthernetX/Y/Z.
func inEthernetPortChannelLaneFormat(s string) bool {
	s = strings.TrimPrefix(s, "Ethernet")
	nums := strings.Split(s, "/")
	if len(nums) != 3 {
		return false
	}
	for _, num := range nums {
		if _, err := strconv.Atoi(num); err != nil {
			return false
		}
	}
	return true
}

// WaitForAllPortsUp waits for all the interfaces of
// the format: EthernetX/Y/Z to be up.
// Returns error if the context expires before all the ports are up.
func WaitForAllPortsUp(ctx context.Context, t *testing.T, dut *ondatra.DUTDevice) error {
	if dut == nil {
		return errors.New("nil DUT passed to WaitForAllPortsUp()")
	}

	// Using ygnmi APIs to avoid fatal error in case of failure.
	yc, err := ygnmiClient(ctx, dut)
	if err != nil {
		return fmt.Errorf("unable to get ygNMI client, err: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, portsUpTimeout)
	defer cancel()

	allInterfaces, err := ygnmi.GetAll(ctx, yc, gnmi.OC().InterfaceAny().Name().Config())
	if err != nil {
		return fmt.Errorf("ygnmi.GetAll for /interfaces/interface/config failed, err: %v", err)
	}

	numPorts := 0
	b := ygnmi.NewWildcardBatch(gnmi.OC().InterfaceAny().OperStatus().State())
	// Create a batch query of all the interfaces of the format: EthernetX/Y/Z
	// to check if they are up.
	for _, intf := range allInterfaces {
		if !inEthernetPortChannelLaneFormat(intf) {
			continue
		}
		enabled, err := ygnmi.Get(ctx, yc, gnmi.OC().Interface(intf).Enabled().Config())
		if err != nil {
			return fmt.Errorf("ygnmi.Get for /interfaces/interface(name=%v)/enabled/config failed, err: %v", intf, err)
		}
		if !enabled {
			continue
		}
		b.AddPaths(gnmi.OC().Interface(intf).OperStatus().State())
		numPorts++
	}

	dutName := dut.Name()
	isUp := map[string]bool{}
	w := ygnmi.WatchAll(ctx, yc, b.Query(), func(v *ygnmi.Value[oc.E_Interface_OperStatus]) error {
		val, ok := v.Val()
		if !ok {
			return ygnmi.Continue
		}
		s, err := ygot.PathToString(v.Path)
		if err != nil {
			log.WarningContextf(ctx, "dut: %v, ygot.PathToString(%v) failed, err: %v", dutName, v.Path, err)
			return ygnmi.Continue
		}
		if val != oc.Interface_OperStatus_UP {
			log.InfoContextf(ctx, "dut: %v, path: %v: %v", dutName, s, val)
			return ygnmi.Continue
		}
		// Add the path string to the list of paths that are up.
		isUp[s] = true
		// If all the paths are up, exit the watch.
		if len(isUp) == numPorts {
			return nil
		}
		return ygnmi.Continue
	})

	// Wait for all the ports to be up.
	_, err = w.Await()
	return err
}

type switchState int

const (
	down switchState = iota
	gnoiAble
	gnmiAble
	portsUp
)

func (s switchState) String() string {
	switch s {
	case down:
		return "down"
	case gnoiAble:
		return "gnoiAble"
	case gnmiAble:
		return "gnmiAble"
	case portsUp:
		return "portsUp"
	default:
		return "unknown"
	}
}

// WaitForSwitchState waits for the switch to be ready.
// Returns when the switch is ready or the context is expired.
func WaitForSwitchState(ctx context.Context, t *testing.T, dut *ondatra.DUTDevice) error {
	if dut == nil {
		return errors.New("nil DUT passed to WaitForSwitchState()")
	}
	dutName := dut.Name()
	log.InfoContextf(ctx, "Polling for switch state to be ready for dut: %v", dutName)
	switchState := down
	ctx, cancel := context.WithTimeout(ctx, switchStateTimeout)
	defer cancel()

	// Poll until the switch is ready or the context is done.
	err := poll(ctx, t, switchStatePollInterval, func() bool {
		switch s := switchState; s {
		case down:
			if err := GNOIAble(t, dut); err != nil {
				log.InfoContextf(ctx, "GNOIAble(dut=%v) failed, err: %v", dutName, err)
				return false
			}
			switchState++
		case gnoiAble:
			if err := GNMIAble(t, dut); err != nil {
				log.InfoContextf(ctx, "GNMIAble(dut=%v) failed, err: %v", dutName, err)
				return false
			}
			switchState++
		case gnmiAble:
			if err := WaitForAllPortsUp(ctx, t, dut); err != nil {
				log.InfoContextf(ctx, "WaitForAllPortsUp(dut=%v) failed, err: %v", dutName, err)
				return false
			}
			switchState++
		case portsUp:
			return true
		}
		return false
	})

	if err == nil {
		log.InfoContextf(ctx, "dut: %v is ready", dutName)
		return nil
	}
	return fmt.Errorf("dut: %v is waiting for state: %v, polling for ready timed out with err: %v", dutName, (switchState + 1), err)
}

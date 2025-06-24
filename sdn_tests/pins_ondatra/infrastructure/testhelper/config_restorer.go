package testhelper

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/grpc"
)

// DUT and CONTROL are the only restorable IDs.
var restorableDUTIDs = map[string]bool{
	"dut":     true,
	"control": true,
}

// buildIgnorePathNotifications builds delete notifications
// from the given ignorePaths.
func buildIgnorePathNotifications(ignorePaths []string) ([]*gpb.Notification, error) {
	var ignorePathNotifications []*gpb.Notification
	for _, ignore := range ignorePaths {
		p, err := ygot.StringToStructuredPath(ignore)
		if err != nil {
			return nil, fmt.Errorf("ygot.StringToStructuredPath(%v) failed, cannot convert ignored path to ygot structured path, err : %v", ignore, err)
		}
		ignorePathNotifications = append(ignorePathNotifications, &gpb.Notification{
			Delete: []*gpb.Path{p},
		})
	}
	return ignorePathNotifications, nil
}

// ConfigRestorer stores config of devices under the reservation.
// Saves current configs when constructed with NewConfigRestorer.
// Tries to restore the config on Close
// and fails the test if the config is not restored.
type ConfigRestorer struct {
	savedConfigs map[string]*oc.Root
	ignorePaths  []*gpb.Notification
}

// NewConfigRestorerWithIgnorePaths
// returns the constructed ConfigRestorer object.
// Accepts a list of paths to ignore when comparing configs.
func NewConfigRestorerWithIgnorePaths(t *testing.T, ignorePaths []string) *ConfigRestorer {
	if t == nil {
		return nil
	}

	cr := &ConfigRestorer{
		savedConfigs: make(map[string]*oc.Root),
	}

	var err error
	// Build ignorePath notifications to easily remove the paths from oc.Root.
	cr.ignorePaths, err = buildIgnorePathNotifications(ignorePaths)
	if err != nil {
		t.Fatal(err)
	}

	devices := ondatra.DUTs(t)
	for id, device := range devices {
		if !cr.isRestorableDUTID(id) {
			log.Infof("Unsupported DUT ID:%v, not saving config for the device(%v)", id, device.Name())
			continue
		}
		if err := cr.saveConfig(device); err != nil {
			t.Fatal(err)
		}
	}

	return cr
}

// NewConfigRestorer returns the constructed ConfigRestorer object.
func NewConfigRestorer(t *testing.T) *ConfigRestorer {
	return NewConfigRestorerWithIgnorePaths(t, nil)
}

func (cr *ConfigRestorer) isRestorableDUTID(dutID string) bool {
	// If needed, use modelx to determine the type of device.
	s := strings.ToLower(dutID)
	_, ok := restorableDUTIDs[s]
	return ok
}

func (cr *ConfigRestorer) rootToJSON(r *oc.Root) (string, error) {
	return ygot.EmitJSON(r, &ygot.EmitJSONConfig{SkipValidation: true})
}

func (cr *ConfigRestorer) removeFPGABridgeAndEndpointComponents(r *oc.Root) {
	for k := range r.Component {
		if strings.HasSuffix(k, "_bridge") || strings.HasSuffix(k, "_endpoint") {
			delete(r.Component, k)
		}
	}
}

// notificationsToOCRoot converts the notifications to oc.Root.
func (cr *ConfigRestorer) notificationsToOCRoot(notifications []*gpb.Notification) (*oc.Root, error) {
	// Append ignorePaths to notifications to remove the paths from oc.Root.
	notifications = append(notifications, cr.ignorePaths...)
	s, err := oc.Schema()
	if err != nil {
		return nil, fmt.Errorf("oc.Schema() failed with err : %v", err)
	}
	// Was unable to unmarshal the notifications without PreferShadowPath options.
	if err := ytypes.UnmarshalNotifications(s, notifications, &ytypes.IgnoreExtraFields{}, &ytypes.PreferShadowPath{}, &ytypes.BestEffortUnmarshal{}); err != nil {
		log.Infof("ytypes.UnmarshalNotifications() has err : %v", err)
	}
	r, ok := s.Root.(*oc.Root)
	if !ok {
		return nil, fmt.Errorf("failed to convert the schema root to oc.Root")
	}
	cr.removeFPGABridgeAndEndpointComponents(r)
	return r, nil
}

// switchConfig returns the current config of the switch.
// GNMI GET of config is not same as the default model config
// as the fetched config contains extra fields.
func (cr *ConfigRestorer) switchConfig(dut *ondatra.DUTDevice) (*oc.Root, error) {
	getReq := &gpb.GetRequest{
		Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
		Path:     []*gpb.Path{},
		Type:     gpb.GetRequest_CONFIG,
		Encoding: gpb.Encoding_JSON_IETF, // Using JSON_IETF to unmarshal the notifications to oc.Root struct.
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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

	return cr.notificationsToOCRoot(getResp.GetNotification())
}

func (cr *ConfigRestorer) saveConfig(device *ondatra.DUTDevice) error {
	conf, err := cr.switchConfig(device)
	if err != nil {
		return fmt.Errorf("fetching switchConfig(%v) failed with err : %v", device.Name(), err)
	}
	cr.savedConfigs[device.Name()] = conf
	return nil
}

// configChanged compares the current config of the device with its saved config.
// returns diff between the configs.
func (cr *ConfigRestorer) configChanged(t *testing.T, device *ondatra.DUTDevice) (string, error) {
	deviceName := device.Name()
	log.Infof("Checking %v for config changes.", deviceName)
	conf, err := cr.switchConfig(device)
	if err != nil {
		return "", fmt.Errorf("fetching switchConfig(DUTDevice=%v) failed with err : %v", deviceName, err)
	}
	var diff string
	if diff = cmp.Diff(conf, cr.savedConfigs[deviceName]); diff == "" {
		log.Infof("no diff in configs found for DUTDevice=%v", deviceName)
		return "", nil
	}
	log.Infof("diff in configs found for DUTDevice=%v, diff_begin:\n%v\ndiff_end\n", deviceName, diff)
	return diff, nil
}

// restoreConfig tries to restore the config of the device by:
//
//	Push the default config to the device.
//	Check if there is still a difference between the saved config,
//	if so, return error.
func (cr *ConfigRestorer) restoreConfig(t *testing.T, device *ondatra.DUTDevice) error {
	deviceName := device.Name()
	log.Infof("Trying to restore config for device(%v) by pushing default config\n", deviceName)
	err := ConfigPush(t, device, nil)
	if err != nil {
		return fmt.Errorf("config push to device(%v) failed due to err : %v", deviceName, err)
	}

	// Check if ConfigPush is enough to restore the config.
	diff, err := cr.configChanged(t, device)
	if err != nil {
		return fmt.Errorf("restoring config failed with err : %v", err)
	}
	if diff == "" {
		log.Infof("config restored for device=%v.", deviceName)
		return nil
	}
	log.Infof("Config diff found even after config push for device=%v\ndiff_begin:\n%v\ndiff_end\n", deviceName, diff)
	return fmt.Errorf("couldn't restore config for device=%v after config push", deviceName)
}

// restoreConfigOnDiff checks if there is a diff between
// the current config and the saved config.
// If there is a diff, try to restore the config.
func (cr *ConfigRestorer) restoreConfigOnDiff(t *testing.T, device *ondatra.DUTDevice) error {
	diff, err := cr.configChanged(t, device)
	if err != nil {
		return fmt.Errorf("err in finding config changes, err : %v", err)
	}
	if diff == "" {
		return nil
	}
	log.Infof("Config diff found for device=%v\ndiff_begin:\n%v\ndiff_end\n", device.Name(), diff)
	if err = cr.restoreConfig(t, device); err != nil {
		return fmt.Errorf("restoreConfig(dut=%v) failed with err : %v", device.Name(), err)
	}
	return nil
}

// restoreReservedDevices tries to restore the config of the reserved devices
// if the config differs from the saved config.
func (cr *ConfigRestorer) restoreReservedDevices(t *testing.T) {
	if cr.savedConfigs == nil {
		log.Infof("configRestorer.savedConfigs is not initialized.")
		return
	}

	devices := ondatra.DUTs(t)
	for id, device := range devices {
		deviceName := device.Name()
		if !cr.isRestorableDUTID(id) {
			log.Infof("Unsupported DUT ID:%v, not restoring config for the device(%v)", id, deviceName)
			continue
		}
		if err := cr.restoreConfigOnDiff(t, device); err != nil {
			t.Error(err)
		}
	}
}

// RestoreConfigsAndClose restores the config of reserved devices
// and closes the configRestorer object.
func (cr *ConfigRestorer) RestoreConfigsAndClose(t *testing.T) {
	cr.restoreReservedDevices(t)
	cr.savedConfigs = nil
	cr.ignorePaths = nil
}

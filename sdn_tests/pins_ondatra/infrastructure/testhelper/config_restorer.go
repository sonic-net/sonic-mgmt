package testhelper

import (
	"context"
        "errors"
	"fmt"
	"strings"
        "sync"
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
        syspb "github.com/openconfig/gnoi/system"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygot/ygot"
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
			return nil, fmt.Errorf("ygot.StringToStructuredPath(path=%v) failed, cannot convert ignored path to ygot structured path, err : %v", ignore, err)
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
        mu           sync.Mutex
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
		t.Fatalf("buildIgnorePathNotifications failed, err : %v", err)
	}

        ctx := context.Background()
	wg := sync.WaitGroup{}
	devices := ondatra.DUTs(t)
        errCh := make(chan error, len(devices))
	for id, device := range devices {
		if !cr.isRestorableDUTID(id) {
			log.InfoContextf(ctx, "Unsupported DUT ID: %v, not saving config for the device: %v", id, device.Name())
			continue
		}
                wg.Add(1)
		go func(device *ondatra.DUTDevice) {
			defer wg.Done()
			errCh <- cr.saveConfig(ctx, device)
		}(device)
	}
	wg.Wait()
	close(errCh)

        // collect all the errors and fail the test on error.
	if err := collectErrors(errCh); err != nil {
		t.Fatalf("config_restorer creation failed, errors: %v", err)
	}

        // Register a cleanup to restore the configs on test end.
	t.Cleanup(func() {
		cr.RestoreConfigsAndClose(t)
	})
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

// switchConfigAsOCRoot returns the current config of the switch as a go struct.
// GNMI GET of config is not same as the default model config
// as the fetched config contains extra fields.
// switchConfigAsOCRoot returns the switch config as a go struct.
func (cr *ConfigRestorer) switchConfigAsOCRoot(ctx context.Context, dut *ondatra.DUTDevice) (*oc.Root, error) {
	getReq := &gpb.GetRequest{
		Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
		Path:     []*gpb.Path{},
		Type:     gpb.GetRequest_CONFIG,
		Encoding: gpb.Encoding_JSON_IETF, // Using JSON_IETF to unmarshal the notifications to oc.Root struct.
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
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

	notifications := getResp.GetNotification()
	// Append ignorePaths to notifications to remove the paths from oc.Root.
	notifications = append(notifications, cr.ignorePaths...)
	r, err := UnmarshalConfigNotificationsToOCRoot(notifications)
	if err != nil {
		return nil, fmt.Errorf("UnmarshalConfigNotificationsToOCRoot(notifications=%v) failed: %v", notifications, err)
	}
	cr.removeFPGABridgeAndEndpointComponents(r)
	return r, nil
}

func (cr *ConfigRestorer) saveConfig(ctx context.Context, device *ondatra.DUTDevice) error {
	conf, err := cr.switchConfigAsOCRoot(ctx, device)
	if err != nil {
		return fmt.Errorf("fetching switchConfig(%v) failed with err : %v", device.Name(), err)
	}
        // Acquire mutex to write to savedConfigs map.
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.savedConfigs[device.Name()] = conf
	return nil
}

// configChanged compares the current config of the device with its saved config.
// returns diff between the configs.
func (cr *ConfigRestorer) configChanged(ctx context.Context, t *testing.T, device *ondatra.DUTDevice) (bool, error) {
	deviceName := device.Name()
	log.InfoContextf(ctx, "Checking device: %v for config changes", deviceName)
	conf, err := cr.switchConfigAsOCRoot(ctx, device)
	if err != nil {
		return true, fmt.Errorf("fetching switchConfig for device: %v failed with err: %v", deviceName, err)
	}
	diff := cmp.Diff(conf, cr.savedConfigs[deviceName])
	if diff == "" {
		log.InfoContextf(ctx, "no diff in configs found for device: %v", deviceName)
		return false, nil
	}
	log.InfoContextf(ctx, "diff in configs found for device: %v\ndiff_begin:\n%v\ndiff_end\n", deviceName, diff)
	return true, nil
}

func (cr *ConfigRestorer) reboot(ctx context.Context, t *testing.T, device *ondatra.DUTDevice) error {
	deviceName := device.Name()
	log.InfoContextf(ctx, "Trying to restore config for device: %v by rebooting\n", deviceName)
	waitTime, err := RebootTimeForDevice(t, device)
	if err != nil {
		return fmt.Errorf("RebootTimeForDevice(dut=%v) failed, err: %v", deviceName, err)
	}
	req := &syspb.RebootRequest{
		Method:  syspb.RebootMethod_COLD,
		Message: "rebooting to apply config",
	}
	if err := Reboot(t, device, &RebootParams{
		request:       req,
		waitTime:      waitTime,
		checkInterval: 10 * time.Second,
	}); err != nil {
		return fmt.Errorf("Reboot(dut=%v) failed, err: %v", deviceName, err)
	}
	return WaitForSwitchState(ctx, t, device)
}

// restoreConfigOnDiff checks if there is a diff between
// the current config and the saved config.
// If there is a diff, try to restore the config.
func (cr *ConfigRestorer) restoreConfigOnDiff(ctx context.Context, t *testing.T, device *ondatra.DUTDevice) error {
	changed, err := cr.configChanged(ctx, t, device)
	if err != nil {
		return fmt.Errorf("err in finding config changes, err: %v", err)
	}
	if changed == false {
		return nil
	}

	log.InfoContextf(ctx, "Trying to restore config for device: %v by pushing default config\n", device.Name())
	if err := ConfigPushAndWaitForConvergence(ctx, t, device, nil /*(config)*/); err != nil {
		log.InfoContextf(ctx, "ConfigPushAndWaitForConvergence(dut=%v) failed, err: %v", device.Name(), err)
		return cr.reboot(ctx, t, device)
	}
	if err := WaitForSwitchState(ctx, t, device); err != nil {
		log.InfoContextf(ctx, "WaitForSwitchState(dut=%v) failed, err: %v", device.Name(), err)
		return cr.reboot(ctx, t, device)
	}
	return nil
}

// restoreReservedDevices tries to restore the config of the reserved devices
// if the config differs from the saved config.
func (cr *ConfigRestorer) restoreReservedDevices(t *testing.T) {
        t.Helper()
	ctx := context.Background()
	if cr.savedConfigs == nil {
		log.InfoContextf(ctx, "configRestorer.savedConfigs is not initialized.")
		return
	}

        wg := sync.WaitGroup{}
	devices := ondatra.DUTs(t)
        errCh := make(chan error, len(devices))
	for id, device := range devices {
		deviceName := device.Name()
		if !cr.isRestorableDUTID(id) {
			log.InfoContextf(ctx, "Unsupported DUT ID:%v, not restoring config for the device: %v", id, deviceName)
			continue
		}
		wg.Add(1)
		go func(t *testing.T, device *ondatra.DUTDevice) {
			defer wg.Done()
			if err := cr.restoreConfigOnDiff(ctx, t, device); err != nil {
				errCh <- fmt.Errorf("couldn't restore config for device: %v, err: %v", device.Name(), err)
			}
		}(t, device)
	}
	wg.Wait()
	close(errCh)

        // Collect all the errors and fail the test on error.
	if err := collectErrors(errCh); err != nil {
		t.Fatalf("failed to restore config, errors: %v", err)
	}
        log.InfoContextf(ctx, "Config restored for all the reserved devices.")
}

// RestoreConfigsAndClose restores the config of reserved devices
// and closes the configRestorer object.
func (cr *ConfigRestorer) RestoreConfigsAndClose(t *testing.T) {
        t.Helper()
	cr.restoreReservedDevices(t)
	cr.savedConfigs = nil
	cr.ignorePaths = nil
}

func collectErrors(errCh chan error) error {
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

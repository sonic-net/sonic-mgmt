package testhelper

// This file contains helper method for gNOI services such as
// Reboot, Install etc.
import (
	"context"
	"fmt"
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/pkg/errors"

	healthzpb "github.com/openconfig/gnoi/healthz"
	syspb "github.com/openconfig/gnoi/system"
)

// Function pointers that interact with the switch. They enable unit testing
// of methods that interact with the switch.
var (
	gnoiSystemClientGet = func(t *testing.T, d *ondatra.DUTDevice) syspb.SystemClient {
		return d.RawAPIs().GNOI(t).System()
	}

	gnoiHealthzClientGet = func(t *testing.T, d *ondatra.DUTDevice) healthzpb.HealthzClient {
		return d.RawAPIs().GNOI(t).Healthz()
	}

	gnmiSystemBootTimeGet = func(t *testing.T, d *ondatra.DUTDevice) uint64 {
		return gnmi.Get(t, d, gnmi.OC().System().BootTime().State())
	}
)

// RebootParams specify the reboot parameters used by the Reboot API.
type RebootParams struct {
	request       any
	waitTime      time.Duration
	checkInterval time.Duration
	lmTTkrID      string // latency measurement testtracker UUID
	lmTitle       string // latency measurement title
}

// NewRebootParams returns RebootParams structure with default values.
func NewRebootParams() *RebootParams {
	return &RebootParams{
		waitTime:      4 * time.Minute,
		checkInterval: 20 * time.Second,
	}
}

// WithWaitTime adds the period of time to wait for the reboot operation to be
// successful.
func (p *RebootParams) WithWaitTime(t time.Duration) *RebootParams {
	p.waitTime = t
	return p
}

// WithCheckInterval adds the time interval to check whether the reboot
// operation has been successful.
func (p *RebootParams) WithCheckInterval(t time.Duration) *RebootParams {
	p.checkInterval = t
	return p
}

// WithRequest adds the reboot request in RebootParams. The reboot request can
// be one of the following:
// 1) RebootMethod such as syspb.RebootMethod_COLD.
// 2) RebootRequest protobuf.
func (p *RebootParams) WithRequest(r any) *RebootParams {
	p.request = r
	return p
}

// WithLatencyMeasurement adds testtracker uuid and title for latency measurement.
func (p *RebootParams) WithLatencyMeasurement(testTrackerID, title string) *RebootParams {
	p.lmTTkrID = testTrackerID
	p.lmTitle = title
	return p
}

// measureLatency returns true if latency measurement parameters are set and valid.
func (p *RebootParams) measureLatency() bool {
	return p.waitTime > 0 && p.lmTitle != ""
}

// Reboot sends a RebootRequest message to the switch. It waits for a specified
// amount of time for the switch reboot to be successful. A switch reboot is
// considered to be successful if the gNOI server is up and the boot time is
// after the reboot request time.
func Reboot(t *testing.T, d *ondatra.DUTDevice, params *RebootParams) error {
	if params.waitTime < params.checkInterval {
		return errors.Errorf("wait time:%v cannot be less than check interval:%v", params.waitTime, params.checkInterval)
	}

	var req *syspb.RebootRequest
	switch v := params.request.(type) {
	case syspb.RebootMethod:
		// User only specified the reboot type. Construct reboot request.
		req = &syspb.RebootRequest{
			Method:  v,
			Message: "Reboot",
		}
	case *syspb.RebootRequest:
		// Use the specified reboot request.
		req = v
	default:
		return errors.New("invalid reboot request (valid parameters are RebootRequest protobuf and RebootMethod)")
	}

	log.Infof("Rebooting %v switch", testhelperDUTNameGet(d))
	timeBeforeReboot := time.Now().UnixNano()
	systemClient := gnoiSystemClientGet(t, d)

	if _, err := systemClient.Reboot(context.Background(), req); err != nil {
		return errors.Wrapf(err, "reboot RPC failed")
	}

	if params.waitTime == 0 {
		// User did not request a wait time which implies that the API did not verify whether
		// the switch has rebooted or not. Therefore, do not return an error in this case.
		return nil
	}

	log.Infof("Polling gNOI server reachability in %v intervals for max duration of %v", params.checkInterval, params.waitTime)
	for timeout := time.Now().Add(params.waitTime); time.Now().Before(timeout); {
		// The switch backend might not have processed the request or might take
		// sometime to execute the request. So wait for check interval time and
		// later verify that the switch rebooted within the specified wait time.
		time.Sleep(params.checkInterval)
		doneTime := time.Now()
		timeElapsed := (doneTime.UnixNano() - timeBeforeReboot) / int64(time.Second)

		if err := GNOIAble(t, d); err != nil {
			log.Infof("gNOI server not up after %v seconds", timeElapsed)
			continue
		}
		log.Infof("gNOI server up after %v seconds", timeElapsed)

		// An extra check to ensure that the system has rebooted.
		if bootTime := gnmiSystemBootTimeGet(t, d); bootTime < uint64(timeBeforeReboot) {
			log.Infof("Switch has not rebooted after %v seconds", timeElapsed)
			continue
		}

		log.Infof("Switch rebooted after %v seconds", timeElapsed)
		return nil
	}

	err := errors.Errorf("failed to reboot %v", testhelperDUTNameGet(d))

	return err
}

// GNOIAble returns whether the gNOI server on the specified device is reachable
// or not.
func GNOIAble(t *testing.T, d *ondatra.DUTDevice) error {
	// Time() gNOI request is used to verify the gNOI server reachability.
	_, err := gnoiSystemClientGet(t, d).Time(context.Background(), &syspb.TimeRequest{})
	return err
}

// HealthzGetPortDebugData returns port debug data given an interface.
func HealthzGetPortDebugData(t *testing.T, d *ondatra.DUTDevice, intfName string) error {
	return fmt.Errorf("unimplemented method HealthzGetPortDebugData")
}

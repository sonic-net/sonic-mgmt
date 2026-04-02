package testhelper

// This file contains helper method for gNOI services such as
// Reboot, Install etc.
import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	healthzpb "github.com/openconfig/gnoi/healthz"
	syspb "github.com/openconfig/gnoi/system"
	"github.com/openconfig/gnoigo"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/binding/grpcutil"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"testing"
	"time"
)

// Function pointers that interact with the switch. They enable unit testing
// of methods that interact with the switch.
var (
	gnoiClientGet = func(t *testing.T, d *ondatra.DUTDevice) (gnoigo.Clients, error) {
		ctx, cancel := grpcutil.WithDefaultTimeout(context.Background(), time.Minute)
		defer cancel()
		return d.RawAPIs().BindingDUT().DialGNOI(ctx, grpc.WithBlock())
	}

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
	request        any
	waitTime       time.Duration
	checkInterval  time.Duration
	requestTimeout time.Duration
	lmTTkrID       string // latency measurement testtracker UUID
	lmTitle        string // latency measurement title
}

// NewRebootParams returns RebootParams structure with default values.
func NewRebootParams() *RebootParams {
	return &RebootParams{
		waitTime:       4 * time.Minute,
		checkInterval:  20 * time.Second,
		requestTimeout: 2 * time.Minute,
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

// WithRequestTimeout adds the timeout for the reboot request.
// The function will wait for the gNOI server to be down within this duration.
// Default value is 2 minutes.
func (p *RebootParams) WithRequestTimeout(timeout time.Duration) *RebootParams {
	p.requestTimeout = timeout
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

	dutName := testhelperDUTNameGet(d)
	log.Infof("Rebooting %v switch", dutName)
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

	rebootRequestTimeout := params.requestTimeout
	ctx, cancel := context.WithTimeout(context.Background(), rebootRequestTimeout)
	defer cancel()

	// The switch backend might not have processed the request or might take
	// sometime to execute the request. So poll for the gNOI server to be down,
	// or context to expire.
	pollErr := poll(ctx, 10*time.Second /*(pollInterval)*/, func() pollStatus {
		err := GNOIAble(t, d)
		timeElapsed := (time.Now().UnixNano() - timeBeforeReboot) / int64(time.Second)
		if err == nil {
			log.Infof("%v: gNOI server is still up after %v seconds", dutName, timeElapsed)
			return continuePoll
		}
		log.Infof("%v: gNOI server is down after %v seconds, got error while checking gNOI server reachability: %v as expected", dutName, timeElapsed, err)
		return exitPoll
	})
	if pollErr != nil {
		log.WarningContextf(ctx, "%v: Polling gNOI server to be down within time: %v failed: %v", dutName, rebootRequestTimeout, pollErr)
		log.InfoContextf(ctx, "%v: Continue to check if the switch has rebooted", dutName)
	}

	log.InfoContextf(ctx, "%v: Polling gNOI server reachability in %v intervals for max duration of %v", dutName, params.checkInterval, params.waitTime)
	for timeout := time.Now().Add(params.waitTime); time.Now().Before(timeout); {
		time.Sleep(params.checkInterval)
		doneTime := time.Now()
		timeElapsed := (doneTime.UnixNano() - timeBeforeReboot) / int64(time.Second)

		if err := GNOIAble(t, d); err != nil {
			log.InfoContextf(ctx, "%v: gNOI server not up after %v seconds", dutName, timeElapsed)
			continue
		}
		log.InfoContextf(ctx, "%v: gNOI server up after %v seconds", dutName, timeElapsed)

		// An extra check to ensure that the system has rebooted.
		if bootTime := gnmiSystemBootTimeGet(t, d); bootTime < uint64(timeBeforeReboot) {
			log.InfoContextf(ctx, "%v: Switch has not rebooted after %v seconds", dutName, timeElapsed)
			continue
		}

		log.InfoContextf(ctx, "%v: Switch rebooted after %v seconds", dutName, timeElapsed)
		return nil
	}

	err := errors.Errorf("%v: failed to reboot", dutName)

	return err
}

// GNOIAble returns whether the gNOI server on the specified device is reachable
// or not.
func GNOIAble(t *testing.T, d *ondatra.DUTDevice) error {
	gnoiClient, err := gnoiClientGet(t, d)
	if err != nil {
		return err
	}

        // Time() gNOI request is used to verify the gNOI server reachability.
	_, err = gnoiClient.System().Time(context.Background(), &syspb.TimeRequest{})
	return err
}

// HealthzGetPortDebugData returns port debug data given an interface.
func HealthzGetPortDebugData(t *testing.T, d *ondatra.DUTDevice, intfName string) error {
	return fmt.Errorf("unimplemented method HealthzGetPortDebugData")
}

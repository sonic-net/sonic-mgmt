package testhelper

// This file contains helper method for gNOI services such as
// Reboot, Install etc.
import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"

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

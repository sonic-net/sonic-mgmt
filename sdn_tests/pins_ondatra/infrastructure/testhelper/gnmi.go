package testhelper

import (
	"context"
	"testing"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc/system"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

// Function pointers that interact with the switch. They enable unit testing
// of methods that interact with the switch.
var (
	gnmiSystemBootTimePath = func() *system.System_BootTimePath {
		return gnmi.OC().System().BootTime()
	}
	gnmiSubscribeClientGet = func(t *testing.T, d *ondatra.DUTDevice, ctx context.Context, opts ...grpc.CallOption) (gpb.GNMI_SubscribeClient, error) {
		c, err := d.RawAPIs().BindingDUT().DialGNMI(ctx)
		if err != nil {
			return nil, err
		}
		return c.Subscribe(ctx, opts...)
	}
	gnmiSet = func(t *testing.T, d *ondatra.DUTDevice, req *gpb.SetRequest) (*gpb.SetResponse, error) {
		ctx := context.Background()
		c, err := d.RawAPIs().BindingDUT().DialGNMI(ctx)
		if err != nil {
			return nil, err
		}
		return c.Set(ctx, req)
	}
)

// GNMIConfig provides an interface to implement config get.
type GNMIConfig interface {
	ConfigGet() ([]byte, error)
}

// GNMIConfigDUT contains the DUT for which the config get is being requested for.
type GNMIConfigDUT struct {
	DUT *ondatra.DUTDevice
}

// SubscribeRequestParams specifies the parameters that are used to create the
// SubscribeRequest.
// Target: The target to be specified in the prefix.
// Paths: List of paths to be added in the request.
// Mode: Subscription mode.
type SubscribeRequestParams struct {
	Target string
	Paths  []ygnmi.PathStruct
	Mode   gpb.SubscriptionList_Mode
}

// CreateSubscribeRequest creates SubscribeRequest message using the specified
// parameters that include the list of paths to be added in the request.
func CreateSubscribeRequest(params SubscribeRequestParams) (*gpb.SubscribeRequest, error) {
	prefix := &gpb.Path{Origin: "openconfig"}
	prefix.Target = params.Target

	var subscriptions []*gpb.Subscription
	for _, path := range params.Paths {
		resolvedPath, _, errs := ygnmi.ResolvePath(path)
		if errs != nil {
			return nil, errors.New("failed to resolve Openconfig path")
		}

		subscription := &gpb.Subscription{
			Path: &gpb.Path{Elem: resolvedPath.Elem},
		}
		subscriptions = append(subscriptions, subscription)
	}

	return &gpb.SubscribeRequest{
		Request: &gpb.SubscribeRequest_Subscribe{
			Subscribe: &gpb.SubscriptionList{
				Prefix:       prefix,
				Subscription: subscriptions,
				Mode:         params.Mode,
				Encoding:     gpb.Encoding_PROTO,
			},
		},
	}, nil
}

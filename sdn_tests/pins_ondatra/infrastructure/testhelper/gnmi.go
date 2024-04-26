package testhelper

import (
	"context"
	"os"
	"testing"

	closer "github.com/openconfig/gocloser"
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

// GNMIAble returns whether the gNMI server on the specified device is reachable
// or not.
func GNMIAble(t *testing.T, d *ondatra.DUTDevice) error {
	// Since the Ondatra Get() API panics in case of failure, we need to use
	// raw gNMI client to test reachability with the gNMI server on the switch.
	// The gNMI server reachability is checked by fetching the system boot-time
	// path from the switch.
	params := SubscribeRequestParams{
		Target: testhelperDUTNameGet(d),
		Paths:  []ygnmi.PathStruct{gnmiSystemBootTimePath()},
		Mode:   gpb.SubscriptionList_ONCE,
	}
	subscribeRequest, err := CreateSubscribeRequest(params)
	if err != nil {
		return errors.Wrapf(err, "failed to create SubscribeRequest")
	}

	subscribeClient, err := gnmiSubscribeClientGet(t, d, context.Background())
	if err != nil {
		return errors.Wrapf(err, "unable to get subscribe client")
	}
	defer closer.CloseAndLog(subscribeClient.CloseSend, "error closing gNMI send stream")

	if err := subscribeClient.Send(subscribeRequest); err != nil {
		return errors.Wrapf(err, "failed to send gNMI subscribe request")
	}

	if _, err := subscribeClient.Recv(); err != nil {
		return errors.Wrapf(err, "subscribe client Recv() failed")
	}

	return nil
}

// ConfigGet returns a full config for the given DUT.
func (d GNMIConfigDUT) ConfigGet() ([]byte, error) {
	return os.ReadFile("infrastructure/data/config.json")
}

// ConfigPush pushes the given config onto the DUT. If nil is passed in for config,
// this function will use ConfigGet() to get a full config for the DUT.
func ConfigPush(t *testing.T, dut *ondatra.DUTDevice, config *[]byte) error {
	if dut == nil {
		return errors.New("nil DUT passed into ConfigPush()")
	}
	if config == nil {
		getConfig, err := GNMIConfigDUT{dut}.ConfigGet()
		if err != nil {
			return err
		}
		config = &getConfig
	}
	setRequest := &gpb.SetRequest{
		Prefix: &gpb.Path{Origin: "openconfig", Target: testhelperDUTNameGet(dut)},
		Replace: []*gpb.Update{{
			Path: &gpb.Path{},
			Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: *config}},
		}},
	}
	t.Logf("Pushing config on %v: %v", testhelperDUTNameGet(dut), setRequest)
	_, err := gnmiSet(t, dut, setRequest)
	return err
}

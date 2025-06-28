package testhelper

import (
	"context"
        "fmt"
	"os"
	"testing"
        "time"

	closer "github.com/openconfig/gocloser"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
        "github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/gnmi/oc/system"
	"github.com/openconfig/ygnmi/ygnmi"
        "github.com/openconfig/ygot/ytypes"
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
func (d GNMIConfigDUT) ConfigGet(t *testing.T) ([]byte, error) {
	return os.ReadFile("ondatra/data/config.json")
}

// ConfigPush pushes the given config onto the DUT. If nil is passed in for config,
// this function will use ConfigGet() to get a full config for the DUT.
func ConfigPush(t *testing.T, dut *ondatra.DUTDevice, config []byte) error {
	if dut == nil {
		return errors.New("nil DUT passed into ConfigPush()")
	}
        var err error
	if config == nil {
		config, err = GNMIConfigDUT{dut}.ConfigGet(t)
		if err != nil {
			return err
		}
	}
	setRequest := &gpb.SetRequest{
		Prefix: &gpb.Path{Origin: "openconfig", Target: testhelperDUTNameGet(dut)},
		Replace: []*gpb.Update{{
			Path: &gpb.Path{},
			Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: config}},
		}},
	}
	t.Logf("Pushing config on %v: %v", testhelperDUTNameGet(dut), setRequest)
	_, err = gnmiSet(t, dut, setRequest)
	return err
}

// unmarshalNotificationsToOCRoot unpacks notifications to oc.Root struct.
// If preferConfigPath is true, the config path is preferred over the state path
// while unmarshalling into oc.Root.
func unmarshalNotificationsToOCRoot(notifications []*gpb.Notification, preferConfigPath bool) (*oc.Root, error) {
	s, err := oc.Schema()
	if err != nil {
		return nil, fmt.Errorf("oc.Schema() failed with err : %v", err)
	}
	opts := []ytypes.UnmarshalOpt{
		&ytypes.IgnoreExtraFields{},
		&ytypes.BestEffortUnmarshal{},
	}
	if preferConfigPath {
		opts = append(opts, &ytypes.PreferShadowPath{})
	}
	err = ytypes.UnmarshalNotifications(
		s,
		notifications,
		opts...,
	)
	if err != nil {
		if _, ok := err.(*ytypes.ComplianceErrors); !ok {
			return nil, fmt.Errorf("ytypes.UnmarshalNotifications() failed with err : %v", err)
		}
	}
	r, ok := s.Root.(*oc.Root)
	if !ok {
		return nil, fmt.Errorf("failed to convert the schema root to oc.Root")
	}
	return r, nil
}

// UnmarshalStateNotificationsToOCRoot unpacks notifications and
// returns the Root GO struct
func UnmarshalStateNotificationsToOCRoot(n []*gpb.Notification) (*oc.Root, error) {
	return unmarshalNotificationsToOCRoot(n, false /*(preferConfigPath)*/)
}

// UnmarshalConfigNotificationsToOCRoot unpacks notifications and
// returns the Root GO struct
func UnmarshalConfigNotificationsToOCRoot(n []*gpb.Notification) (*oc.Root, error) {
	return unmarshalNotificationsToOCRoot(n, true /*(preferConfigPath)*/)
}

// ygnmiClient returns a new ygnmi client for the dut.
// YGNMI APIs don't call fatal on error whereas the GNMI APIs do.
func ygnmiClient(ctx context.Context, dut *ondatra.DUTDevice) (*ygnmi.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("DialGNMI() failed: %v", err)
	}
	return ygnmi.NewClient(gnmiClient, ygnmi.WithTarget(dut.Name()))
}

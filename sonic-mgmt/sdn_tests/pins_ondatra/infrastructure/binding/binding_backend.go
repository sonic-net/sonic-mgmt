// Package bindingbackend describes the interface to interact with the reservations and devices.
package bindingbackend

import (
	"context"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra/binding"
	opb "github.com/openconfig/ondatra/proto"
	"google.golang.org/grpc"
)

// ReservedTestbed contains information about reserved testbed.
type ReservedTestbed struct {
	id   string // Reservation id
	name string
}

// Device contains data of reserved switch.
type Device struct {
	Name    string
	ID      string
	PortMap map[string]*binding.Port
}

// GRPCService represents supported grpc service.
type GRPCService string

const (
	// GNMI represents gnmi grpc service.
	GNMI GRPCService = "gnmi"
	// GNOI represents gnoi grpc service.
	GNOI GRPCService = "gnoi"
	// GNSI represents gnsi grpc service.
	GNSI GRPCService = "gnsi"
	// P4RT represents p4rt grpc service.
	P4RT GRPCService = "p4rt"
)

// GRPCServices contains addresses for services using grpc protocol.
type GRPCServices struct {
	Addr map[GRPCService]string
}

// HTTPService contains addresses for services using HTTP protocol.
type HTTPService struct {
	Addr string
}

// DUTDevice contains device and service addresses for DUT device.
type DUTDevice struct {
	*Device
	GRPC GRPCServices
}

// ATEDevice contains device and service addresses for ATE device.
type ATEDevice struct {
	*Device
	HTTP HTTPService
}

// ReservedTopology represents the reserved DUT and ATE devices.
type ReservedTopology struct {
	ID   string
	DUTs []*DUTDevice
	ATEs []*ATEDevice
}

// Backend exposes functions to interact with reservations and reserved devices.
type Backend interface {
	// ReserveTopology returns topology of reserved DUT and ATE devices.
	ReserveTopology(ctx context.Context, tb *opb.Testbed, runtime, waittime time.Duration) (*ReservedTopology, error)
	// Release releases the reserved devices, called during teardown.
	Release(ctx context.Context) error
	// DialGRPC connects to grpc service and returns the opened grpc client for use.
	DialGRPC(ctx context.Context, addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error)
	DialConsole(ctx context.Context, dut *binding.AbstractDUT) (binding.ConsoleClient, error)
	// GNMIClient wraps the grpc connection under gnmi client.
	GNMIClient(ctx context.Context, dut *binding.AbstractDUT, conn *grpc.ClientConn) (gpb.GNMIClient, error)

	// Close closes backend's internal objects.
	Close() error
}

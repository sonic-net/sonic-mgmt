// Package pinsbackend can reserve Ondatra DUTs and provide clients to interact with the DUTs.
package pinsbackend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
	"flag"

	log "github.com/golang/glog"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra/binding"
	opb "github.com/openconfig/ondatra/proto"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/bindingbackend"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	supportedSecurityModes = []string{"insecure", "mtls"}
	securityMode = flag.String("security_mode", "insecure", fmt.Sprintf("define the security mode of the conntections to gnmi server, choose from : %v. Uses insecure as default.", supportedSecurityModes))
 )

// Backend can reserve Ondatra DUTs and provide clients to interact with the DUTs.
type Backend struct {
	configs map[string]*tls.Config
}

// New creates a backend object.
func New() *Backend {
	return &Backend{configs: map[string]*tls.Config{}}
}

// registerGRPCTLS caches grpc TLS certificates for the given serverName.
func (b *Backend) registerGRPCTLS(grpc *bindingbackend.GRPCServices, serverName string) error {
	if serverName == "" {
		return fmt.Errorf("serverName is empty")
	}

	// Load certificate of the CA who signed server's certificate.
	pemServerCA, err := os.ReadFile("ondatra/certs/ca_crt.pem")
	if err != nil {
		return err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return fmt.Errorf("failed to add server CA's certificate")
	}
	// Load client's certificate and private key
	clientCert, err := tls.LoadX509KeyPair("ondatra/certs/client_crt.pem", "ondatra/certs/client_key.pem")
	if err != nil {
		return err
	}

	for _, service := range grpc.Addr {
		b.configs[service] = &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      certPool,
			ServerName:   serverName,
			MinVersion:  tls.VersionTLS13,
		}
	}

	return nil
}


// ReserveTopology returns topology containing reserved DUT and ATE devices.
func (b *Backend) ReserveTopology(ctx context.Context, tb *opb.Testbed, runtime, waitTime time.Duration) (*bindingbackend.ReservedTopology, error) {
	// Fill in the Dut and Control device details.
	dut := "192.168.0.1"     // sample dut address.
	control := "192.168.0.2" // sample control address.
	log.Infof("testbed Dut:%s Control switch:%s", dut, control)

	grpcPort := "9339"
	p4rtPort := "9559"
	dutGRPCAddr := fmt.Sprintf("%v:%v", dut, grpcPort)
	dutP4RTAddr := fmt.Sprintf("%v:%v", dut, p4rtPort)
	controlGRPCAddr := fmt.Sprintf("%v:%v", control, grpcPort)
	controlP4RTAddr := fmt.Sprintf("%v:%v", control, p4rtPort)

	// Modify the reservation based on your topology.
	r := &bindingbackend.ReservedTopology{
		ID: "PINS Reservation",
		DUTs: []*bindingbackend.DUTDevice{{
			Device: &bindingbackend.Device{
				ID:   "DUT",
				Name: dut,
				PortMap: map[string]*binding.Port{
					"port1":  {Name: "Ethernet1/1/1"},
					"port2":  {Name: "Ethernet1/1/5"},
					"port3":  {Name: "Ethernet1/2/1"},
					"port4":  {Name: "Ethernet1/2/5"},
					"port5":  {Name: "Ethernet1/3/1"},
					"port6":  {Name: "Ethernet1/3/5"},
					"port7":  {Name: "Ethernet1/4/1"},
					"port8":  {Name: "Ethernet1/4/5"},
					"port9":  {Name: "Ethernet1/5/1"},
					"port10": {Name: "Ethernet1/5/5"},
					"port11": {Name: "Ethernet1/6/1"},
					"port12": {Name: "Ethernet1/6/5"},
					"port13": {Name: "Ethernet1/7/1"},
					"port14": {Name: "Ethernet1/7/5"},
					"port15": {Name: "Ethernet1/8/1"},
					"port16": {Name: "Ethernet1/8/5"},
					"port17": {Name: "Ethernet1/9/1"},
					"port18": {Name: "Ethernet1/9/5"},
					"port19": {Name: "Ethernet1/10/1"},
					"port20": {Name: "Ethernet1/10/5"},
				},
			},
			GRPC: bindingbackend.GRPCServices{
				Addr: map[bindingbackend.GRPCService]string{
					bindingbackend.GNMI: dutGRPCAddr,
					bindingbackend.GNOI: dutGRPCAddr,
					bindingbackend.GNSI: dutGRPCAddr,
					bindingbackend.P4RT: dutP4RTAddr,
				},
			}},
			{
				Device: &bindingbackend.Device{
					ID:   "CONTROL",
					Name: control,
					PortMap: map[string]*binding.Port{
						"port1":  {Name: "Ethernet1/1/1"},
						"port2":  {Name: "Ethernet1/1/5"},
						"port3":  {Name: "Ethernet1/2/1"},
						"port4":  {Name: "Ethernet1/2/5"},
						"port5":  {Name: "Ethernet1/3/1"},
						"port6":  {Name: "Ethernet1/3/5"},
						"port7":  {Name: "Ethernet1/4/1"},
						"port8":  {Name: "Ethernet1/4/5"},
						"port9":  {Name: "Ethernet1/5/1"},
						"port10": {Name: "Ethernet1/5/5"},
						"port11": {Name: "Ethernet1/6/1"},
						"port12": {Name: "Ethernet1/6/5"},
						"port13": {Name: "Ethernet1/7/1"},
						"port14": {Name: "Ethernet1/7/5"},
						"port15": {Name: "Ethernet1/8/1"},
						"port16": {Name: "Ethernet1/8/5"},
						"port17": {Name: "Ethernet1/9/1"},
						"port18": {Name: "Ethernet1/9/5"},
						"port19": {Name: "Ethernet1/10/1"},
						"port20": {Name: "Ethernet1/10/5"},
					},
				},
				GRPC: bindingbackend.GRPCServices{
					Addr: map[bindingbackend.GRPCService]string{
						bindingbackend.GNMI: controlGRPCAddr,
						bindingbackend.GNOI: controlGRPCAddr,
						bindingbackend.GNSI: controlGRPCAddr,
						bindingbackend.P4RT: controlP4RTAddr,
					},
				}},
		}}

	for _, dut := range r.DUTs {
		if err := b.registerGRPCTLS(&dut.GRPC, dut.Name); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// Release releases the reserved devices, called during teardown.
func (b *Backend) Release(ctx context.Context) error {
	return nil
}

// DialGRPC connects to grpc service and returns the opened grpc client for use.
func (b *Backend) DialGRPC(ctx context.Context, addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	if *securityMode  == "mtls" {
	    tlsConfig, ok := b.configs[addr]
	    if !ok {
	   	return nil, fmt.Errorf("failed to find TLS config for %s", addr)
	    }

	    opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
        } else  {
	   opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
 	}
	conn, err := grpc.DialContext(ctx, addr, opts...)
 	if err != nil {
 		return nil, fmt.Errorf("DialContext(%s, %v) : %v", addr, opts, err)
	}
	return conn, nil
}

// DialConsole returns a StreamClient for the DUT.
func (b *Backend) DialConsole(ctx context.Context, dut *binding.AbstractDUT) (binding.ConsoleClient, error) {
	return nil, fmt.Errorf("unimplemented function")
}

// GNMIClient wraps the grpc connection under gnmi client.
func (b *Backend) GNMIClient(ctx context.Context, dut *binding.AbstractDUT, conn *grpc.ClientConn) (gpb.GNMIClient, error) {
	if conn == nil {
		return nil, fmt.Errorf("conn is nil")
	}
	if dut == nil {
		return nil, fmt.Errorf("dut is nil")
	}
	return gpb.NewGNMIClient(conn), nil
}

// Close closes backend's internal objects.
func (b *Backend) Close() error {
	b.configs = nil
	return nil
}

package testhelper

// This file provides helper APIs to perform P4RT related operations.

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	log "github.com/golang/glog"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/prototext"

	p4infopb "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4pb "github.com/p4lang/p4runtime/go/p4/v1"
)

var (
	icName                 = "integrated_circuit0"
	defaultDeviceID uint64 = 183934027

	testhelperPortIDGet = func(t *testing.T, d *ondatra.DUTDevice, port string) (int, error) {
		idInfo, present := gnmi.Lookup(t, d, gnmi.OC().Interface(port).Id().State()).Val()
		if present {
			return int(idInfo), nil
		}
		return 0, errors.Errorf("failed to get port ID for port %v from switch", port)
	}
	testhelperDeviceIDGet = func(t *testing.T, d *ondatra.DUTDevice) (uint64, error) {
		deviceInfo, present := gnmi.Lookup(t, d, gnmi.OC().Component(icName).IntegratedCircuit().State()).Val()
		if present && deviceInfo.NodeId != nil {
			return *deviceInfo.NodeId, nil
		}
		// Configure default device ID on the switch.
		gnmi.Replace(t, d, gnmi.OC().Component(icName).IntegratedCircuit().NodeId().Config(), defaultDeviceID)
		// Verify that default device ID has been configured and return that.
		if got, want := gnmi.Get(t, d, gnmi.OC().Component(icName).IntegratedCircuit().NodeId().State()), defaultDeviceID; got != want {
			return 0, errors.Errorf("failed to configure default device ID")
		}
		return defaultDeviceID, nil
	}
)

// PacketOut structure enables the user to specify the following information for
// performing packet-out operation on the switch:
// EgressPort: Front panel port from which the packet needs to be sent out.
// Count: Number of packets to be egressed.
// Interval: Time interval between successive packet-out operations.
// Packet: Raw packet to be sent out.
type PacketOut struct {
	SubmitToIngress bool
	EgressPort      string
	Count           uint
	Interval        time.Duration
	Packet          []byte
}

// P4RTClient wraps P4RuntimeClient and implements methods for performing P4RT
// operations.
type P4RTClient struct {
	client     p4pb.P4RuntimeClient
	stream     p4pb.P4Runtime_StreamChannelClient
	deviceID   uint64
	electionID *p4pb.Uint128
	isMaster   bool
	dut        *ondatra.DUTDevice
	p4Info     *p4infopb.P4Info
}

// P4RTClientOptions contains the fields for creation of P4RTClient.
type P4RTClientOptions struct {
	p4info *p4infopb.P4Info
}

func generateElectionID() *p4pb.Uint128 {
	// Get time in milliseconds.
	t := uint64(time.Now().UnixNano() / 1000000)
	return &p4pb.Uint128{
		Low:  t % 1000,
		High: t / 1000,
	}
}

// SetMastership tries to configure P4RT client as master by sending master
// arbitration request to the switch.
func (p *P4RTClient) SetMastership() error {
	// Don't take any action if the client is already the master.
	if p.isMaster {
		return nil
	}

	mastershipReq := &p4pb.StreamMessageRequest{
		Update: &p4pb.StreamMessageRequest_Arbitration{
			Arbitration: &p4pb.MasterArbitrationUpdate{
				DeviceId:   p.deviceID,
				ElectionId: p.electionID,
			},
		},
	}

	log.Infof("Sending master arbitration request with DeviceId:%v, ElectionId:%v", p.deviceID, p.electionID)
	if err := p.stream.Send(mastershipReq); err != nil {
		return errors.Wrapf(err, "master arbitration send request failed")
	}

	res, err := p.stream.Recv()
	if err != nil {
		return errors.Wrapf(err, "stream Recv() error")
	}

	arb := res.GetArbitration()
	if arb == nil {
		return errors.Errorf("unexpected response received from switch: %v", res.String())
	}
	if codes.Code(arb.Status.Code) != codes.OK {
		return errors.Errorf("master arbitration failed (response status: %v)", arb.Status)
	}

	log.Infof("Master arbitration successful: client is master")
	p.isMaster = true
	return nil
}

// P4InfoDetails is an interface to get P4Info of a chassis.
type P4InfoDetails interface {
	P4Info() (*p4infopb.P4Info, error)
}

// P4Info gets P4Info of the switch.
func (p *P4RTClient) P4Info() (*p4infopb.P4Info, error) {
	var p4Info *p4infopb.P4Info
	err := fmt.Errorf("P4Info is not implemented")

	// Read P4Info from file.
	p4Info = &p4infopb.P4Info{}
	data, err := os.ReadFile("infrastructure/data/p4rtconfig.prototext")
	if err != nil {
		return nil, err
	}
	err = prototext.Unmarshal(data, p4Info)

	return p4Info, err
}

// FetchP4Info fetches P4Info from the switch.
func (p *P4RTClient) FetchP4Info() (*p4infopb.P4Info, error) {
	req := &p4pb.GetForwardingPipelineConfigRequest{DeviceId: p.deviceID}
	resp, err := p.client.GetForwardingPipelineConfig(context.Background(), req)
	if err != nil {
		return nil, errors.Wrap(err, "GetForwardingPipelineConfig() failed")
	}
	if resp == nil {
		return nil, errors.New("received nil GetForwardingPipelineConfigResponse")
	}
	config := resp.GetConfig()
	if config == nil {
		return nil, nil
	}
	return config.GetP4Info(), nil
}

// PushP4Info pushes P4Info into the switch.
func (p *P4RTClient) PushP4Info() error {
	var err error
	if p.p4Info == nil {
		p.p4Info, err = p.P4Info()
		if err != nil {
			return errors.Wrapf(err, "failed to fetch P4Info")
		}
	}
	config := &p4pb.ForwardingPipelineConfig{
		P4Info: p.p4Info,
	}
	req := &p4pb.SetForwardingPipelineConfigRequest{
		DeviceId:   p.deviceID,
		ElectionId: p.electionID,
		Action:     p4pb.SetForwardingPipelineConfigRequest_RECONCILE_AND_COMMIT,
		Config:     config,
	}

	_, err = p.client.SetForwardingPipelineConfig(context.Background(), req)
	if err != nil {
		return errors.Wrapf(err, "SetForwardingPipelineConfig operation failed")
	}

	log.Infof("P4Info push successful")
	return nil
}

// FetchP4RTClient method fetches P4RTClient associated with a device. If the
// client does not exist, then it creates one and caches it for future use.
// During client creation, it performs master arbitration and P4Info push.
func FetchP4RTClient(t *testing.T, d *ondatra.DUTDevice, p p4pb.P4RuntimeClient, options *P4RTClientOptions) (*P4RTClient, error) {
	p4Client := &P4RTClient{
		client: p,
		dut:    d,
	}
	if options != nil {
		p4Client.p4Info = options.p4info
	}
	var err error
	p4Client.deviceID, err = testhelperDeviceIDGet(t, d)
	if err != nil {
		return nil, err
	}
	// Create stream for master arbitration and packet I/O.
	var streamErr error
	p4Client.stream, streamErr = p4Client.client.StreamChannel(context.Background())
	if streamErr != nil {
		return nil, errors.Wrap(streamErr, "failed to create stream for master arbitration")
	}

	// Configure P4RT client as master.
	p4Client.electionID = generateElectionID()
	if err := p4Client.SetMastership(); err != nil {
		return nil, errors.Wrap(err, "failed to configure P4RT client as master")
	}

	// Push P4Info only if it isn't present in the switch.
	p4Info, err := p4Client.FetchP4Info()
	if err != nil {
		return nil, errors.Wrap(err, "FetchP4Info() failed")
	}
	if p4Info == nil {
		if err := p4Client.PushP4Info(); err != nil {
			return nil, errors.Wrap(err, "P4Info push failed")
		}
	}

	return p4Client, nil
}

// SendPacketOut instructs the P4RT server on the switch to perform packet-out
// operation.
func (p *P4RTClient) SendPacketOut(t *testing.T, packetOut *PacketOut) error {
	// Validate user input parameters.
	if packetOut.SubmitToIngress && packetOut.EgressPort != "" {
		return errors.Errorf("cannot have both SubmitToIngress and EgressPort set in the packet-out request: %+v", packetOut)
	}

	// Metadata value cannot be empty, so dummy value is set and ignored when SubmitToIngress is true.
	portID := "Unused"
	submitToIngress := []byte{0}
	if packetOut.SubmitToIngress {
		submitToIngress = []byte{1}
	} else {
		egressPortID, err := testhelperPortIDGet(t, p.dut, packetOut.EgressPort)
		if err != nil {
			return errors.Errorf("failed to get ID for port %v: %v", packetOut.EgressPort, err)
		}
		portID = strconv.Itoa(egressPortID)
	}

	if packetOut.Count == 0 {
		return errors.Errorf("packet-out count should be > 0 in packet-out request: %+v", packetOut)
	}
	count := packetOut.Count
	interval := packetOut.Interval

	// Prepare packet I/O request.
	pktOut := &p4pb.PacketOut{
		Payload: packetOut.Packet,
	}
	// Add egress_port metadata.
	pktOut.Metadata = append(pktOut.Metadata, &p4pb.PacketMetadata{
		MetadataId: 1,
		Value:      []byte(portID),
	})
	// Add submit_to_ingress metadata.
	pktOut.Metadata = append(pktOut.Metadata, &p4pb.PacketMetadata{
		MetadataId: 2,
		Value:      submitToIngress,
	})
	// Add unused_pad metadata.
	pktOut.Metadata = append(pktOut.Metadata, &p4pb.PacketMetadata{
		MetadataId: 3,
		Value:      []byte{0},
	})
	packetOutReq := &p4pb.StreamMessageRequest{
		Update: &p4pb.StreamMessageRequest_Packet{Packet: pktOut},
	}

	log.Infof("Sending %v packets to the switch at %v interval. Packet:\n%v", count, interval, hex.Dump(packetOut.Packet))
	for c := uint(1); c <= count; c++ {
		// Send packet-out request to the switch.
		if err := p.stream.Send(packetOutReq); err != nil {
			return errors.Errorf("Packet-out request failed for packet number: %v (%v)", c, err)
		}
		// Sleep only if user has specified time interval and more packets need to be sent.
		if interval > 0 && c < count {
			time.Sleep(interval)
		}
	}

	log.Infof("Packet-out operation completed")
	return nil
}

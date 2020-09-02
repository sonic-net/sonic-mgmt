// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package schemafake defines a fake implementation of a gNMI device with
// a known schema which is used to validate tests within the gNMITest
// framework.
package schemafake

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmi/unimplemented"
	"github.com/openconfig/gnmitest/common"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/util"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

var (
	// Timestamp is a function used to specify the timestamp to be used in Notifications
	// returned from the fake. It can be overridden in calling code to ensure that a
	// deterministic result is returned.
	Timestamp = func() int64 { return time.Now().UnixNano() }
)

// Target defines the gNMI fake target.
type Target struct {
	unimplemented.Server                    // Implement the gNMI server interface.
	schema               map[string]*origin // schema is a map, keyed by origin name, of the schemas supported by the fake.
}

// origin stores the internal state for a gNMI target's origins, supporting mixed schema
// operation.
type origin struct {
	mu            sync.RWMutex           // mu is a mutex used to protect access to the origin
	data          ygot.ValidatedGoStruct // data is the datatree stored at the origin.
	unmarshalFunc ytypes.UnmarshalFunc   // unmarshalFunc is a function which can be used to unmarshal into the root.
	rootSchema    *yang.Entry            // rootSchema is the schema of the root node for the YANG schematree.
}

// unmarshal unmarshals the contents of d, which must be valid RFC7951 JSON, to the
// origin with the specified options.
func (o *origin) unmarshal(d []byte, opts ...ytypes.UnmarshalOpt) error {
	if o.unmarshalFunc == nil {
		return errors.New("invalid (nil) unmarshal function")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.unmarshalFunc(d, o.data, opts...)
}

// get returns the value stored at the specified path from the origin.
func (o *origin) get(path *gpb.Path) ([]*ytypes.TreeNode, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return ytypes.GetNode(o.rootSchema, o.data, path, &ytypes.GetPartialKeyMatch{})
}

// New creates a new schemaefake using the specified map of schemas. The schemas map is keyed by the origin
// name, with the value being a Schema specification.
func New(schemas map[string]*ytypes.Schema) (*Target, error) {
	t := &Target{
		schema: map[string]*origin{},
	}

	if len(schemas) == 0 {
		return nil, fmt.Errorf("target must have more than %d schemas specified", len(schemas))
	}

	for sn, s := range schemas {
		sroot, ok := s.SchemaTree[reflect.TypeOf(s.Root).Elem().Name()]
		if !ok {
			return nil, fmt.Errorf("could not find schema for %T in the supplied schema tree for origin %s", sroot, sn)
		}

		t.schema[sn] = &origin{
			data:          reflect.New(reflect.TypeOf(s.Root).Elem()).Interface().(ygot.ValidatedGoStruct),
			rootSchema:    sroot,
			unmarshalFunc: s.Unmarshal,
		}
	}

	return t, nil
}

// Start starts the fake gNMI server with the specified certificate and key. It returns
// the TCP port the fake is listening on, a function to stop the server and an optional
// error if the server cannot be started.
func (t *Target) Start(cert, key string) (uint64, func(), error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, nil, fmt.Errorf("cannot create listener, %v", err)
	}

	creds, err := credentials.NewServerTLSFromFile(cert, key)
	if err != nil {
		return 0, nil, fmt.Errorf("Failed to generate credentials %v", err)
	}

	server := grpc.NewServer(grpc.Creds(creds))

	tcpPort, err := common.ListenerTCPPort(l)
	if err != nil {
		return 0, nil, err
	}

	gpb.RegisterGNMIServer(server, t)
	go server.Serve(l)
	return tcpPort, server.Stop, nil
}

// getOrigin returns the definition from the origin named n from the target's stored
// schemas.
func (t *Target) getOrigin(n string) (*origin, error) {
	if n == "" {
		// According to the specification, "" is equal to "openconfig".
		n = "openconfig"
	}

	originNames := func(o map[string]*origin) []string {
		names := []string{}
		for s := range o {
			names = append(names, s)
		}
		return names
	}

	s, ok := t.schema[n]
	if !ok {
		return nil, fmt.Errorf("could not find origin %s, supported origins %v", n, originNames(t.schema))
	}

	return s, nil
}

// Load unmarshals the JSON supplied in b into the supplied origin,  using the options
// specified into the target's root using the stored unmarshal function.
func (t *Target) Load(b []byte, origin string, opts ...ytypes.UnmarshalOpt) error {
	orig, err := t.getOrigin(origin)
	if err != nil {
		return fmt.Errorf("cannot load data into origin: %v", err)
	}

	if err := orig.unmarshal(b, opts...); err != nil {
		return fmt.Errorf("cannot unmarshal JSON data, %v", err)
	}
	return nil
}

// Subscribe handles the gNMI bi-directional streaming Subscribe RPC.
// SubscribeRequest messages are read from the client, and the target streams
// responses back according to the type of subscription specified.
//
// Currently, this implementation only supports the ONCE subscription mode.
func (t *Target) Subscribe(stream gpb.GNMI_SubscribeServer) error {
	in, err := stream.Recv()
	if err == io.EOF {
		return nil
	}

	if err != nil {
		return err
	}

	switch v := in.GetRequest(); v.(type) {
	case *gpb.SubscribeRequest_Subscribe:
		switch s := in.GetSubscribe(); s.GetMode() {
		case gpb.SubscriptionList_ONCE:
			return t.handleOnce(s, stream)
		default:
			return status.Errorf(codes.Unimplemented, "Subscription modes other than ONCE are not implemented")
		}
	case *gpb.SubscribeRequest_Poll:
		return status.Errorf(codes.Unimplemented, "Poll is unimplemented")
	}

	return nil
}

// handleOnce is a handler for the ONCE RPC, the SubscriptionList received from
// the client is parsed for the paths that are to be exported, which are
// marshalled to gNMI Notifications and written to the supplied stream.
func (t *Target) handleOnce(req *gpb.SubscriptionList, stream gpb.GNMI_SubscribeServer) error {
	msgs, err := t.initialSync(req)
	if err != nil {
		return err
	}

	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			return status.Errorf(codes.Aborted, "cannot send message, %v", err)
		}
	}
	return nil
}

// initialSync is a generic implementation for retrieving the set of paths in the
// supplied req SubscriptionList and returning a set of SubscribeResponse messages
// to be sent to the client. The target appends a sync_response message to the set
// of paths to indicate that the set of paths have been sent - as is required by
// both the initial sync of a STREAM subscription, or a ONCE subscription.
func (t *Target) initialSync(req *gpb.SubscriptionList) ([]*gpb.SubscribeResponse, error) {
	var sr []*gpb.SubscribeResponse
	for _, sub := range req.GetSubscription() {
		// TODO(robjs): Handle prefix being removed from Notifications.
		nodes, _, err := t.getAndPrefix(absolutePath(req.Prefix, sub.Path))
		if err != nil {
			status, ok := status.FromError(err)
			switch {
			case ok && status.Code() == codes.NotFound:
				// Not finding an element in the tree is explictly not an
				// error in Subscribe, invalid paths are handled using
				// InvalidArgument, and hence we ignore this error.
				continue
			default:
				return nil, err
			}
		}

		for _, n := range nodes {
			switch d := n.Data; d.(type) {
			case ygot.GoStruct:
				ns, err := ygot.TogNMINotifications(d.(ygot.GoStruct), Timestamp(), ygot.GNMINotificationsConfig{UsePathElem: true})
				if err != nil {
					return nil, fmt.Errorf("cannot convert path %s into Notifications, %v", n.Path, err)
				}
				for _, u := range ns {
					u.Prefix = n.Path
					sr = append(sr, &gpb.SubscribeResponse{
						Response: &gpb.SubscribeResponse_Update{u},
					})
				}
			default:
				v, err := ygot.EncodeTypedValue(n.Data, gpb.Encoding_PROTO)
				if err != nil {
					return nil, fmt.Errorf("cannot convert scalar data %s into Notifications, %v", n.Path, err)
				}
				sr = append(sr, &gpb.SubscribeResponse{
					Response: &gpb.SubscribeResponse_Update{
						&gpb.Notification{
							Timestamp: Timestamp(),
							Update: []*gpb.Update{{
								Path: n.Path,
								Val:  v,
							}},
						},
					},
				})
			}
		}
	}

	sr = append(sr, &gpb.SubscribeResponse{
		Response: &gpb.SubscribeResponse_SyncResponse{true},
	})
	return sr, nil
}

// absolutePath calculates the absolute path indicated by the prefix and path
// supplied.
func absolutePath(prefix *gpb.Path, path *gpb.Path) *gpb.Path {
	p := path
	if prefix != nil {
		p = &gpb.Path{
			Elem: append(prefix.Elem, path.Elem...),
		}

		if path.GetOrigin() == "" && prefix.GetOrigin() != "" {
			p.Origin = prefix.Origin
		}
	}
	return p
}

// getAndPrefix queries the target's data trees for nodes that correspond to path,
// and returns the data found, along with a prefix that applies to the nodes in
// the query.
func (t *Target) getAndPrefix(path *gpb.Path) ([]*ytypes.TreeNode, *gpb.Path, error) {
	orig, err := t.getOrigin(path.Origin)
	if err != nil {
		return nil, nil, status.Errorf(codes.NotFound, "cannot find origin %s on target, %v", path.Origin, err)
	}

	nodes, err := orig.get(path)
	if err != nil {
		return nil, nil, err
	}

	var prefix *gpb.Path
	if path.Origin != "" || path.Target != "" {
		prefix = &gpb.Path{
			Origin: path.Origin,
			Target: path.Target,
		}
	}

	if len(nodes) > 1 {
		var paths []*gpb.Path
		for _, n := range nodes {
			paths = append(paths, n.Path)
		}
		prefix = util.FindPathElemPrefix(paths)
	}

	return nodes, prefix, nil
}

// Get implements the gNMI Get RPC. The request received from the client is extracted from the
// GetRequest received from the client. Each path is retrieved from the target's data tree,
// and subsequently marshalled into a gNMI Notification. Each path in the GetRequest is
// handled separately, such that there is no guarantee of consistency across separate
// paths within the GetRequest. Prefixing is performed within the results of each
// path expansion within the request.
func (t *Target) Get(ctx context.Context, r *gpb.GetRequest) (*gpb.GetResponse, error) {
	var notifications []*gpb.Notification
	for _, p := range r.Path {
		fullPath := absolutePath(r.Prefix, p)

		// Capture the timestamp for the Notification.
		ts := Timestamp()

		nodes, prefix, err := t.getAndPrefix(fullPath)
		if err != nil {
			return nil, err
		}

		var u []*gpb.Update
		for _, n := range nodes {
			v, err := ygot.EncodeTypedValue(n.Data, r.Encoding)
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "could not encode value at %s, %v", proto.MarshalTextString(n.Path), err)
			}

			u = append(u, &gpb.Update{
				Path: util.TrimGNMIPathElemPrefix(n.Path, prefix),
				Val:  v,
			})
		}

		notifications = append(notifications, &gpb.Notification{
			Timestamp: ts,
			Prefix:    prefix,
			Update:    u,
		})

	}

	return &gpb.GetResponse{Notification: notifications}, nil
}

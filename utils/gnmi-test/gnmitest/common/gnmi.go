/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package common defines operations that are used within the gNMITest
// framework for multiple tests.
package common

import (
	"context"
	//"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	log "github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmitest/creds"
	"google.golang.org/grpc"
	//"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// Connect opens a new gRPC connection to the target speciifed by the
// ConnectionArgs. It returns the gNMI Client connection, and a function
// which can be called to close the connection. If an error is encountered
// during opening the connection, it is returned.
func Connect(ctx context.Context, a *tpb.Connection) (gpb.GNMIClient, func(), error) {
	if a.Address == "" {
		return nil, nil, errors.New("an address must be specified")
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.Timeout)*time.Second)
	defer cancel()

	conn, err := grpc.Dial(a.Address, grpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("cannot dial target %s, %v", a.Address, err)
	}

	return gpb.NewGNMIClient(conn), func() { conn.Close() }, nil
}

// ResolveCredentials takes an input Connection protobuf message and
// resolves the credentials within it using the resolver library.
func ResolveCredentials(ctx context.Context, c *tpb.Connection) (*resolver.Credentials, error) {
	log.Infof("resolving credentials with %s", proto.MarshalTextString(c))
	r, err := resolver.Get(c.GetCredentials().GetResolver()) // returns plaintext if resolver is not set
	if err != nil {
		return nil, fmt.Errorf("cannot get specified resolver, %v", err)
	}

	cr, err := r.Credentials(ctx, c.GetCredentials())
	if err != nil {
		return nil, fmt.Errorf("cannot resolve credentials, %v", err)
	}
	return cr, nil
}

// ContextWithAuth adds authentication details from the supplied credentials
// to ctx.
func ContextWithAuth(ctx context.Context, creds *resolver.Credentials) context.Context {
	if creds == nil {
		return ctx
	}

	return metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"username", creds.Username,
		"password", creds.Password,
	))
}

// ListenerTCPPort returns the TCP port that is associated with the listener provided.
func ListenerTCPPort(n net.Listener) (uint64, error) {
	t, ok := n.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("cannot parse listen port from %v, not TCP? %T", n.Addr(), n.Addr())
	}
	return uint64(t.Port), nil
}

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

package common

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmi/unimplemented"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmitest/creds"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

var (
	testMsg = &gpb.GetResponse{Notification: []*gpb.Notification{{Timestamp: 42}}}
)

type gnmiServer struct {
	unimplemented.Server
}

// Get implements the Get RPC for the faked gNMI server.
func (g *gnmiServer) Get(_ context.Context, r *gpb.GetRequest) (*gpb.GetResponse, error) {
	return testMsg, nil
}

func TestConnect(t *testing.T) {
	tcpPort, srvStop, err := startGNMIServer("testdata/good.crt", "testdata/good.key")
	if err != nil {
		t.Fatalf("failed to start gNMI server; %v", err)
	}
	defer srvStop()

	tests := []struct {
		name             string
		inArgs           *tpb.Connection
		wantMsg          *gpb.GetResponse
		wantErrSubstring string
	}{{
		name:    "successful connection",
		wantMsg: testMsg,
		inArgs:  &tpb.Connection{Address: fmt.Sprintf("localhost:%d", tcpPort), Timeout: 2},
	}, {
		name:             "failed connection",
		inArgs:           &tpb.Connection{},
		wantErrSubstring: "an address must be specified",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			client, cc, err := Connect(ctx, tt.inArgs)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}

			if err != nil {
				return
			}
			defer cc()

			if tt.wantMsg == nil {
				return
			}

			got, err := client.Get(ctx, &gpb.GetRequest{})
			if err != nil {
				t.Fatalf("did not successfully make Get RPC, %v", err)
			}
			if !proto.Equal(got, tt.wantMsg) {
				diff := pretty.Compare(got, tt.wantMsg)
				t.Fatalf("did not get expected GetResponse, %v", diff)
			}
		})
	}
}

// startGNMIServer starts a gNMI server and returns the tcp port server is listening
// and a callback to stop the server. An error is returned if anything
// goes wrong.
func startGNMIServer(cert, key string) (uint64, func(), error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, nil, fmt.Errorf("cannot create listener, %v", err)
	}

	creds, err := credentials.NewServerTLSFromFile(cert, key)
	if err != nil {
		return 0, nil, fmt.Errorf("Failed to generate credentials %v", err)
	}

	server := grpc.NewServer(grpc.Creds(creds))
	addrParts := strings.Split(l.Addr().String(), ":")
	tcpPort, err := strconv.ParseUint(addrParts[len(addrParts)-1], 10, 16)
	if err != nil {
		return 0, nil, fmt.Errorf("cannot parse listen port from %v, %v", l.Addr(), err)
	}

	gpb.RegisterGNMIServer(server, &gnmiServer{})
	go server.Serve(l)
	return tcpPort, server.Stop, nil
}

type testResolver struct{}

func (r *testResolver) Credentials(_ context.Context, _ *tpb.Credentials) (*resolver.Credentials, error) {
	return &resolver.Credentials{
		Username: "testuser",
		Password: "testpassword",
	}, nil
}

func TestResolveCredentials(t *testing.T) {
	if err := resolver.Set("test", &testResolver{}); err != nil {
		t.Fatalf("cannot register test resolver, %v", err)
	}

	tests := []struct {
		name             string
		in               *tpb.Connection
		want             *resolver.Credentials
		wantErrSubstring string
	}{{
		name: "nil connection",
	}, {
		name: "missing resolver",
		in: &tpb.Connection{
			Credentials: &tpb.Credentials{
				Resolver: "invalid",
			},
		},
		wantErrSubstring: `creds resolver with "invalid" key doesn't exist`,
	}, {
		name: "resolver called",
		in: &tpb.Connection{
			Credentials: &tpb.Credentials{
				Resolver: "test",
			},
		},
		want: &resolver.Credentials{
			Username: "testuser",
			Password: "testpassword",
		},
	}, {
		name: "credentails in proto",
		in: &tpb.Connection{
			Credentials: &tpb.Credentials{
				Username: "robjs",
				Password: "robjs",
			},
		},
		want: &resolver.Credentials{
			Username: "robjs",
			Password: "robjs",
		},
	}, {
		name: "no credentials",
		in:   &tpb.Connection{},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveCredentials(context.Background(), tt.in)

			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}

			if err != nil {
				return
			}

			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Fatalf("did not get expected result, diff(-go,+want):\n%s", diff)
			}
		})
	}
}

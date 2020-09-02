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

// Package main contains an implementation of a gRPC service which
// can be used to execute the gNMI test framework. It does not include
// any target implementation.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"

	log "github.com/golang/glog"
	"github.com/openconfig/gnmi/client/gnmi"
	"github.com/openconfig/gnmitest/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/openconfig/gnmitest/proto/gnmitest"
)

var (
	gnmiTestPort = 11601
	gnmiTestBind = "localhost"
	servicePort  = flag.Int("port", gnmiTestPort, "Test service port.")
	bind         = flag.String("bind", gnmiTestBind, "Test service host to bind on.")
)

// runTestService starts gnmitest service. If a port isn't provided, function
// picks a port automatically.
func runTestService(ctx context.Context) error {
	// Create a grpc Server.
	srv := grpc.NewServer()
	testSrv, err := service.NewServer(client.Type)
	if err != nil {
		return fmt.Errorf("failed to create an instance of gnmitest server; %v", err)
	}

	pb.RegisterGNMITestServer(srv, testSrv)

	// Register listening port and start serving.
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *bind, *servicePort))
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	reflection.Register(srv)
	go srv.Serve(lis)
	defer srv.Stop()
	<-ctx.Done()
	return ctx.Err()
}

func main() {
	flag.Parse()

	// Start the gNMI test service.
	log.Exit(runTestService(context.Background()))
}

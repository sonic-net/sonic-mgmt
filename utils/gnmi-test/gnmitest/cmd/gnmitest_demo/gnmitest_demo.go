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

// Package main contains implementation to start gnmitest service. It also
// starts a fake gNMI agent that sends gNMI SubscribeResponse messages
// provided in the textproto file.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"regexp"

	log "github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmi/client/gnmi"
	"github.com/openconfig/gnmi/testing/fake/gnmi"
	"github.com/openconfig/gnmitest/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	fpb "github.com/openconfig/gnmi/testing/fake/proto"
	pb "github.com/openconfig/gnmitest/proto/gnmitest"
)

var (
	servicePort       = flag.Int("service_port", 0, "Test service port.")
	fakeAgentName     = flag.String("fake_agent_name", "", "Name of the fake gNMI agent.")
	fakeAgentPort     = flag.Int("fake_agent_port", 0, "Fake gNMI agent port.")
	fakeAgentTextFile = flag.String("fake_agent_textproto", "", "Textproto file that contains gNMI SubscribeResponse messages to be sent by fake gNMI agent.")

	// pickedPortCh allows users of runTestService to wait until port is defined.
	pickedPortCh = make(chan int, 2)
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
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *servicePort))
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	// Set the port if it is automatically chosen.
	if *servicePort == 0 {
		*servicePort = lis.Addr().(*net.TCPAddr).Port
	}
	pickedPortCh <- *servicePort

	reflection.Register(srv)
	go srv.Serve(lis)
	defer srv.Stop()
	<-ctx.Done()
	return ctx.Err()
}

// createAgent creates a fake agent and starts listening. When a client is connected,
// fake agent sends provided SubscribeResponse messages.
func createAgent(t string, m []*gpb.SubscribeResponse, port int32) (*gnmi.Agent, error) {
	cfg := &fpb.Config{
		Target:     t,
		Port:       port,
		ClientType: fpb.Config_GRPC_GNMI,
		Generator: &fpb.Config_Fixed{
			Fixed: &fpb.FixedGenerator{
				Responses: m,
			},
		},
	}
	a, err := gnmi.New(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent for %q; %v", t, err)
	}
	return a, nil
}

// splitByBlankLine splits the given string by blank line.
func splitByBlankLine(str string) []string {
	removeBlankLines := regexp.MustCompile("\r\n").ReplaceAllString(str, "\n")
	return regexp.MustCompile(`\n\s*\n`).Split(removeBlankLines, -1)
}

// messages function reads the messages corresponding to given target and
// unmarshals them into a slice of *gpb.SubscribeResponse. It returns an error
// if it fails to find testdata or can't unmarshal input.
func messages(f string) ([]*gpb.SubscribeResponse, error) {
	absPath := filepath.Join("testdata", f)
	b, err := ioutil.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q; %v", absPath, err)
	}

	m := []*gpb.SubscribeResponse{}

	for _, s := range splitByBlankLine(string(b)) {
		sr := &gpb.SubscribeResponse{}
		err = proto.UnmarshalText(s, sr)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal %v", string(b))
		}
		m = append(m, sr)
	}

	return m, nil
}

func main() {
	flag.Parse()

	// Get messages from the given textproto file.
	m, err := messages(*fakeAgentTextFile)
	if err != nil {
		log.Exit(err)
	}

	// Create a fake gNMI agent to use as a target in Suite proto.
	a, err := createAgent(*fakeAgentName, m, int32(*fakeAgentPort))
	if err != nil {
		log.Exit(err)
	}
	defer a.Close()

	// Start the gNMI test service.
	log.Exit(runTestService(context.Background()))
}

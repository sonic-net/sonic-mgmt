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

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"flag"
	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmitest/common/report"
	"google.golang.org/grpc"

	gtpb "github.com/openconfig/gnmitest/proto/gnmitest"
	rpb "github.com/openconfig/gnmitest/proto/report"
	spb "github.com/openconfig/gnmitest/proto/suite"
)

var (
	suiteTextProto = flag.String("suite_file", "suite", "Suite text proto file to run against gnmitest service.")
)

// TestGNMITestService starts a gnmitest service and calls its Run RPC by
// providing Suite proto. Run RPC returns Report proto. TestGNMITestService
// checks whether all the tests in the report have status of success.
func TestGNMITestService(t *testing.T) {
	go func() {
		if err := runTestService(context.Background()); err != nil {
			t.Fatalf("failed running gnmitest service; %v", err)
		}
	}()

	// Get the suite proto file.
	s, err := suite(*suiteTextProto)
	if err != nil {
		t.Fatalf("got error %v", err)
	}

	// Extract the set of targets specified in Suite proto.
	target := targets(s)

	// Keeps host:port addresses for each fake agent started.
	addresses := map[string]string{}

	// Iterate through target names and start a fake agent for each of them.
	for _, tt := range target {
		// Unmarshal messages from text file corresponding to its name.
		m, err := messages(fmt.Sprintf("%v.textproto", tt))
		if err != nil {
			t.Fatalf("messages(%q) failed; %v", tt, err)
		}

		// Create a fake agent and start listening.
		a, err := createAgent(tt, m, 0)
		if err != nil {
			t.Fatalf("agent failed %v", a)
		}
		defer a.Close()

		// Save the address to use later while fixing Suite proto.
		addresses[tt] = a.Address()
	}

	// Go through all Connection proto messages in Suite and fix the addresses
	// to point to fake agents.
	fixAddresses(s, addresses)

	// Start running Suite proto.
	rep, err := validateSchemaPath(context.Background(), fmt.Sprintf("localhost:%d", <-pickedPortCh), s)
	if err != nil {
		t.Fatalf("running Suite failed; %v", err)
	}

	if !report.AllTestsPassed(rep) {
		t.Errorf("schema validation report has failed tests; %v", rep)
	}
}

// validateSchemaPath connects to gnmitest service running at given address. Calls the Run RPC
// of the gnmitest service. Function either returns a Report proto or an error.
func validateSchemaPath(ctx context.Context, address string, s *spb.Suite) (*rpb.Report, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("grpc.Dial failed for %q", address)
	}
	defer conn.Close()

	cl := gtpb.NewGNMITestClient(conn)

	rep, err := cl.Run(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("running Suite failed; %v", err)
	}
	return rep, nil
}

// targets function extracts the set of targets used in Suite proto.
func targets(s *spb.Suite) []string {
	var result []string
	seen := make(map[string]bool)

	if s.GetConnection().GetTarget() != "" {
		result = append(result, s.GetConnection().GetTarget())
		seen[s.GetConnection().GetTarget()] = true
	}

	for _, ig := range s.GetInstanceGroupList() {
		for _, i := range ig.GetInstance() {
			t := i.GetTest().GetConnection().GetTarget()
			if t == "" {
				continue
			}
			if _, ok := seen[t]; !ok {
				seen[t] = true
				result = append(result, t)
			}
		}
	}
	return result
}

// fixAddresses goes through all Connection proto messages and overrides their
// address fields.
func fixAddresses(s *spb.Suite, a map[string]string) {
	for _, ig := range s.GetInstanceGroupList() {
		for _, i := range ig.GetInstance() {
			switch {
			case i.GetTest() == nil:
			case i.GetTest().GetConnection() != nil:
				if _, ok := a[i.GetTest().GetConnection().GetTarget()]; ok {
					i.GetTest().Connection.Address = a[i.GetTest().GetConnection().GetTarget()]
				}
			}
		}
	}

	if _, ok := a[s.GetConnection().GetTarget()]; ok {
		s.Connection.Address = a[s.GetConnection().GetTarget()]
	}
}

// suite function reads the suite proto text file from the local testdata
// directory in current working directory. It returns Suite proto by
// unmarshaling text proto. It may return error if it fails to unmarshal text
// proto file.
func suite(f string) (*spb.Suite, error) {
	absPath := filepath.Join("testdata", fmt.Sprintf("%v.textproto", f))
	b, err := ioutil.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q; %v", absPath, err)
	}

	s := &spb.Suite{}
	if err = proto.UnmarshalText(string(b), s); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %v", string(b))
	}

	return s, nil
}

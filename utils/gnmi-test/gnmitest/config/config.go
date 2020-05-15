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

// Package config creates a wrapper around Suite proto message. It is consumed
// by runner while running tests. Config package also performs basic validation
// as well as fixing overridden fields in Test proto messages.
package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/schemas/openconfig/register"

	spb "github.com/openconfig/gnmitest/proto/suite"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

const (
	// defaultTimeout is the duration a test is allowed to run. If neither test
	// nor suite specifies a timeout, defaultTimeout is used.
	defaultTimeout = 1 * time.Minute
	// Default schema to use in tests if not specified by individual tests or Suite
	// proto.
	defaultSchema = openconfig.Key
)

// Config is a container for high level information needed by runner.
type Config struct {
	// Client type to try while subscribing to target.
	ClientType string
	// Suite proto that represents test configuration.
	Suite *spb.Suite
}

// New creates a Config reference with an initialized Suite proto inside.
func New(b []byte, clientType string) (*Config, error) {
	s := &spb.Suite{}
	if err := proto.UnmarshalText(string(b), s); err != nil {
		return nil, err
	}

	// setOverridden sets some of the fields of Test proto message if they are left
	// empty. Running setOverridden ensures that runner is handed a Suite proto
	// that doesn't need resolution.
	if err := setOverridden(s); err != nil {
		return nil, fmt.Errorf("failed to fix overridden fields; %v", err)
	}

	if err := validate(s); err != nil {
		return nil, err
	}

	return &Config{
		Suite:      s,
		ClientType: clientType,
	}, nil
}

// validateTest function checks whether test is registered and attempts to get an instance
// of the test with the args provided in Suite proto. Validation can fail due to reasons like
// test is not registered or test args aren't correct.
func validateTest(t *tpb.Test) error {
	switch v := t.Type.(type) {
	case *tpb.Test_Subscribe:
		// Make sure that test is registered and can be initialized without an error.
		if _, err := register.GetSubscribeTest(v.Subscribe.Args, t); err != nil {
			return fmt.Errorf("got error while validating %T subscribe test; %v", v.Subscribe.Args, err)
		}
	case *tpb.Test_GetSet, *tpb.Test_FakeTest:
		// GetSet and FakeTest do not require registration.
		return nil
	default:
		return fmt.Errorf("framework doesn't support running %T test", v)
	}
	return nil
}

// validate goes through each test referenced in Suite proto message and checks whether tests are
// registered and can be initialized successfully. This gives a chance to fail a Suite proto early
// instead of during running individual tests.
func validate(s *spb.Suite) error {
	// validate tests in Instances
	for _, ig := range s.InstanceGroupList {
		for _, i := range ig.Instance {
			if err := validateTest(i.Test); err != nil {
				return err
			}
		}
	}

	// validate tests in extensions
	for _, v := range s.ExtensionList {
		for _, e := range v.Extension {
			if err := validateTest(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// setOverridden iterates over Test proto messages in Suite proto and tries to
// set missing fields of Test proto messages.
func setOverridden(s *spb.Suite) error {
	for _, ig := range s.GetInstanceGroupList() {
		for _, i := range ig.GetInstance() {
			if err := setConnection(i.GetTest(), s.GetConnection()); err != nil {
				return err
			}

			setSchema(i.GetTest(), s.GetSchema())
			setTimeout(i.GetTest(), s.GetTimeout())
		}
	}
	return nil
}

// setSchema fixes test schema if it isn't specifed by test.
func setSchema(t *tpb.Test, suiteSchema string) {
	switch {
	case t.Schema != "":
		return
	case suiteSchema != "":
		t.Schema = suiteSchema
	default:
		t.Schema = defaultSchema
	}
}

// setConnection fixes test connection if it isn't specified by test.
func setConnection(t *tpb.Test, suiteConn *tpb.Connection) error {
	switch {
	case t.GetConnection() != nil:
		return nil
	case suiteConn != nil:
		t.Connection = suiteConn
	default:
		// Suite proto should set the connection if Test proto doesn't set.
		return errors.New("connection should be specified either in Test or Suite proto")
	}
	return nil
}

// setTimeout fixes test timeout if it isn't specified by test.
func setTimeout(t *tpb.Test, d int32) {
	switch {
	case t.Timeout > 0:
		return
	case d > 0:
		t.Timeout = d
	default:
		t.Timeout = int32(defaultTimeout / time.Second)
	}
}

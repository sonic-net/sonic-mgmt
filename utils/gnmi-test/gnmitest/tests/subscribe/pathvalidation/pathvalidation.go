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

// Package pathvalidation implements subscribe.Test interface and registers
// factory function to registry. It validates whether paths in received gNMI
// notifications are OpenConfig schema compliant.
package pathvalidation

import (
	"fmt"
	"reflect"

	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/schemas"
	"github.com/openconfig/gnmitest/subscribe"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/ygot"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// test stores the information that doesn't change during the course
// of message stream.
type test struct {
	subscribe.Test
	destStruct ygot.GoStruct
	schema     *yang.Entry
}

// init registers the factory function of the test to global tests registry.
func init() {
	register.NewSubscribeTest(&tpb.SubscribeTest_PathValidation{}, newTest)
}

// newTest is used as a callback by registry to instantiate the test when needed.
// It receives the SubscribeTest proto which contains the arguments to the test
// as well gNMI SubscribeRequest. This test uses neither any arguments nor the
// subscription request.
func newTest(st *tpb.Test) (subscribe.Subscribe, error) {
	goStruct, err := schema.Get(st.GetSchema())
	if err != nil {
		return nil, fmt.Errorf("failed to get %v schema; %v", st.GetSchema(), err)
	}
	// Device GoStruct is the root container within generated GoStructs.
	destStruct := goStruct.NewRoot()
	tn := reflect.TypeOf(destStruct).Elem().Name()
	schema, err := goStruct.Schema(tn)
	if err != nil {
		return nil, fmt.Errorf("failed to get schema for %q; %v", tn, err)
	}

	return &test{
		destStruct: destStruct,
		schema:     schema,
	}, nil
}

// Process function is the interface function for subscribe.Test. It checks whether
// received gNMI SubscribeResponse is OpenConfig compliant.
func (t *test) Process(sr *gpb.SubscribeResponse) (subscribe.Status, error) {
	return subscribe.OneShotGetOrCreate(t.schema, t.destStruct, sr)
}

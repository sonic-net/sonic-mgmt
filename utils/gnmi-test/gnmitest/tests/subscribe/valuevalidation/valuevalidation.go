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

// Package valuevalidation contains gnmitest test that attempts to unmarshal
// received SubscribeResponse updates into GoStruct. If the update is a sync
// update, test is completed.
package valuevalidation

import (
	"fmt"
	"reflect"

	"github.com/openconfig/gnmitest/common/testerror"
	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/schemas"
	"github.com/openconfig/gnmitest/subscribe"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// test stores the state for the test that is independent of each update.
type test struct {
	subscribe.Test
	// dataTree is the tree for Notifications to be deserialised into.
	dataTree ygot.GoStruct
	// schema is the root entry for the schema.
	schema *yang.Entry
}

// init statically registers the test against the gnmitest framework.
func init() {
	register.NewSubscribeTest(&tpb.SubscribeTest_ValueValidation{}, newTest)
}

// newTest creates a new instance of the test. It receives a copy of the SubscribeTest
// proto with the arguments that were received.
func newTest(st *tpb.Test) (subscribe.Subscribe, error) {
	goStruct, err := schema.Get(st.GetSchema())
	if err != nil {
		return nil, fmt.Errorf("failed to get %v schema; %v", st.GetSchema(), err)
	}
	root := goStruct.NewRoot()
	tn := reflect.TypeOf(root).Elem().Name()
	schema, err := goStruct.Schema(tn)
	if err != nil {
		return nil, err
	}
	if schema == nil {
		return nil, fmt.Errorf("schema not found; %v", tn)
	}

	return &test{
		dataTree: root,
		schema:   schema,
	}, nil
}

// Process is called when SubscribeResponse messages are received for the test. It
// deserialises each subscription response into the dataTree. When the sync_response
// message is received, it returns Complete status.
func (t *test) Process(sr *gpb.SubscribeResponse) (subscribe.Status, error) {
	return subscribe.OneShotSetNode(t.schema, t.dataTree, sr, &ytypes.InitMissingElements{})
}

// Check function is called when Process function returns Complete,
// test times out or subscription fails.
func (t *test) Check() error {
	errs := &testerror.List{}
	uErrs := ytypes.Validate(t.schema, t.dataTree)
	for _, e := range uErrs {
		errs.AddErr(e)
	}

	return errs
}

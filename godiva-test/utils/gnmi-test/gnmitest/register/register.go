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

// Package register contains lookup table to get an instance of test.Subscribe.
// Exported NewSubscribeTest function is used by individual tests to register.
package register

import (
	"fmt"
	"reflect"
	"sync"

	log "github.com/golang/glog"
	"github.com/openconfig/gnmitest/subscribe"

	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// SubscribeFunc is used by test framework to instantiate a new instance
// of the test.
type SubscribeFunc func(args *tpb.Test) (subscribe.Subscribe, error)

var (
	// Used by exported New function for thread safe registration.
	mu sync.Mutex
	// subscribeTests is map of registered subscribe tests to the framework.
	// Individual tests register by using init() in their package. In SubscribeTest
	// proto message, type of the args field corresponding to test is used as key.
	// Value is a factory function that returns an instance of the test.
	subscribeTests = make(map[reflect.Type]SubscribeFunc)
)

// NewSubscribeTest registers given test to the framework. First argument is an instance of
// oneof field type in tests proto. Second argument is a factory function that
// creates an instance of the test. Registration is illustrated below for
// SubscribeTest_FirstTest (corresponding field in the proto is written as "first_test")
//
// register.NewSubscribeTest(&tests_pb.SubscribeTest_FirstTest{}, someFunc)
func NewSubscribeTest(te interface{}, f SubscribeFunc) {
	mu.Lock()
	defer mu.Unlock()
	ty := reflect.TypeOf(te)
	if _, ok := subscribeTests[ty]; ok {
		log.Warningf("%T is already registered test type, it will be overridden", te)
	}
	subscribeTests[ty] = f
}

// GetSubscribeTest returns an instance of the test.
func GetSubscribeTest(i interface{}, args *tpb.Test) (subscribe.Subscribe, error) {
	mu.Lock()
	defer mu.Unlock()
	t, ok := subscribeTests[reflect.TypeOf(i)]
	if !ok {
		return nil, fmt.Errorf("%T is not a registered test type", i)
	}
	ti, err := t(args)
	if err != nil {
		return nil, err
	}
	return ti, nil
}

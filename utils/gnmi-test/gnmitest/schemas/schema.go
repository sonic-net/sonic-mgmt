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

// Package schema exports functions to register given schema information
// into lookup table as well as to retrieve from lookup table.
package schema

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
)

// unmarshalFunc defines a type which represents the Unmarshal function in
// ygot generated code.
type unmarshalFunc func([]byte, ygot.GoStruct, ...ytypes.UnmarshalOpt) error

// schemaTreeFunc defines a type which represents the UnzipSchema function in
// ygot generated code.
type schemaTreeFunc func() (map[string]*yang.Entry, error)

// goStruct stores the information related to generated GoStruct.
type goStruct struct {
	// root stores the GoStruct which is the root of the tree.
	root ygot.GoStruct
	// schemaTreeFn can be used to get a copy of schema tree from the generated
	// code.
	schemaTreeFn schemaTreeFunc
	// unmarshalFunc defines the function that can be used to JSON unmarshal
	// into the tree.
	unmarshal unmarshalFunc
}

var (
	// mu is used to synchronize registration of multiple GoStruct
	// into goStructs table.
	mu sync.Mutex
	// goStructs is the lookup table that maintains different goStructs
	// to choose from.
	goStructs = make(map[string]goStruct)
)

// TestGoStruct stores a cached copy of the global schema tree that is local to
// a given test so as to prevent the possiblity of cross-test schema contamination.
type TestGoStruct struct {
	goStruct
	localSchemaTree map[string]*yang.Entry
}

// NewRoot creates a new instance of root ygot.GoStruct.
func (s *TestGoStruct) NewRoot() ygot.GoStruct {
	return reflect.New(reflect.TypeOf(s.root).Elem()).Interface().(ygot.GoStruct)
}

// Schema returns the *yang.Entry corresponding to given key.
func (s *TestGoStruct) Schema(k string) (*yang.Entry, error) {
	if s.localSchemaTree == nil {
		var err error
		// Create a copy of schema tree and use it in subsequent calls to
		// Schema function.
		if s.localSchemaTree, err = s.schemaTreeFn(); err != nil {
			return nil, fmt.Errorf("failed to get schema tree for %q; %v", k, err)
		}
	}
	if _, ok := s.localSchemaTree[k]; !ok {
		return nil, fmt.Errorf("cannot find schema for %q", k)
	}
	return s.localSchemaTree[k], nil
}

// Set registers given key and GoStruct into the registration table.
// If key already exists, it doesn't register GoStruct and returns an error.
func Set(key string, root ygot.GoStruct, stfn schemaTreeFunc, ufn unmarshalFunc) error {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := goStructs[key]; ok {
		return fmt.Errorf("another schema is registered with the key %v", key)
	}
	goStructs[key] = goStruct{
		root:         root,
		schemaTreeFn: stfn,
		unmarshal:    ufn,
	}
	return nil
}

// Get returns reference to testGoStruct so that test can have access to
// underlying schema corresponding to given key.
func Get(key string) (*TestGoStruct, error) {
	mu.Lock()
	defer mu.Unlock()
	gs, ok := goStructs[key]
	if !ok {
		return nil, fmt.Errorf("no schema found corresponding to %q key", key)
	}
	return &TestGoStruct{
		goStruct: gs,
	}, nil
}

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

package schema

import (
	"reflect"
	"testing"

	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmitest/schemas/openconfig"
	"github.com/openconfig/goyang/pkg/yang"
)

func reset() {
	goStructs = make(map[string]goStruct)
}

func TestSingleSchema(t *testing.T) {
	defer reset()
	key := "oc"
	rootStruct := &gostructs.Device{}
	schemaTree := map[string]*yang.Entry{
		"x": &yang.Entry{},
	}
	schemaTreeFn := func() (map[string]*yang.Entry, error) {
		return map[string]*yang.Entry{
			"x": &yang.Entry{},
		}, nil
	}

	if err := Set(key, rootStruct, schemaTreeFn, nil); err != nil {
		t.Fatalf("Schema(%v, %v, schemaTreeFn, nil): got error %v, want no error", key, rootStruct, err)
	}

	c, err := Get(key)
	if err != nil {
		t.Fatalf("Get(%q): got %v, want no error", key, err)
	}

	if nr := c.NewRoot(); nr == rootStruct {
		t.Error("NewRoot(): got identical ygot.GoStruct, want not the same")
	} else if !reflect.DeepEqual(nr, rootStruct) {
		t.Error("NewRoot(): got not equal ygot.GoStruct, want equal")
	}

	for k := range schemaTree {
		if ns, _ := c.Schema(k); ns == schemaTree[k] {
			t.Errorf("Schema(%q): got identical *yang.Entry, want not the same", k)
		} else if !reflect.DeepEqual(ns, schemaTree[k]) {
			t.Errorf("Schema(%q): got not equal *yang.Entry, want equal", k)
		}
	}
}

func TestMultipleSchema(t *testing.T) {
	defer reset()
	k1, k2 := "oc", "oc2"
	if err := Set(k1, nil, nil, nil); err != nil {
		t.Fatalf("Set(%q, nil, nil, nil): got %v, want nil", k1, err)
	}

	if err := Set(k1, nil, nil, nil); err == nil {
		t.Fatalf("Set(%q, nil, nil, nil): got nil, want err", k1)
	}

	if err := Set(k2, nil, nil, nil); err != nil {
		t.Fatalf("Set(%q, nil, nil, nil): got %v, want nil", k2, err)
	}
}

func TestGet(t *testing.T) {
	defer reset()
	key := "arbitrary"

	// test getting schema witha an unregistered key
	wantErr := "no schema found corresponding to"
	_, err := Get(key)
	if diff := errdiff.Substring(err, wantErr); diff != "" {
		t.Fatalf("Get(%q): got %v, want %v", key, err, wantErr)
	}

	// register a schema
	if err := Set(key, nil, nil, nil); err != nil {
		t.Fatalf("Set(%q, nil, nil, nil): got %v, want nil", key, err)
	}

	// "arbitrary" key is now registered, Get must succeed
	if _, err := Get(key); err != nil {
		t.Fatalf("Get(%q): got %v, want no error", key, err)
	}
}

func TestIntegration(t *testing.T) {
	defer reset()

	key := "arbitrary"
	if err := Set(key, &gostructs.Device{}, gostructs.UnzipSchema, gostructs.Unmarshal); err != nil {
		t.Fatalf("Set: registering schema failed for %q; %v", key, err)
	}

	gs, err := Get(key)
	if err != nil {
		t.Fatalf("Get(%q): got %v, want no error", key, err)
	}

	// Device GoStruct is the root container within generated GoStructs.
	destStruct := gs.NewRoot()
	tn := reflect.TypeOf(destStruct).Elem().Name()

	// gs.Schema returns a copy of schema tree.
	sch, err := gs.Schema(tn)
	if err != nil {
		t.Fatalf("Schema(%v): got %v, want no error", tn, err)
	}
	if sch == nil {
		t.Fatalf("Schema(%v): got nil schema", tn)
	}

	if !reflect.DeepEqual(gostructs.SchemaTree[tn], sch) {
		t.Errorf("\ngot %v, \nwant %v", gostructs.SchemaTree[tn], sch)
	}
}

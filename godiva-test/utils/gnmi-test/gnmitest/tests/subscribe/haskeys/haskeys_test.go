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

package haskeys

import (
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmitest/schemas/openconfig/register"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/ygot"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

func path(p string) *gpb.Path {
	path, err := ygot.StringToStructuredPath(p)
	if err != nil {
		panic(err)
	}
	return path
}

func noti(prefixPath string, updatePath string) *gpb.SubscribeResponse {
	return &gpb.SubscribeResponse{
		Response: &gpb.SubscribeResponse_Update{
			Update: &gpb.Notification{
				Prefix: path(prefixPath),
				Update: []*gpb.Update{
					&gpb.Update{
						Path: path(updatePath),
					},
				},
			},
		},
	}
}

func TestCompletePaths(t *testing.T) {
	tests := []struct {
		desc             string
		in               *tpb.SubscribeTest
		want             []*gpb.Path
		wantErrSubstring string
	}{{
		desc:             "nil HasKeys argument",
		in:               &tpb.SubscribeTest{},
		wantErrSubstring: "did not specify an argument",
	}, {
		desc: "list schema is nil",
		in: &tpb.SubscribeTest{
			Args: &tpb.SubscribeTest_HasKeys{
				&tpb.HasKeys{
					Path: nil,
				},
			},
		},
		wantErrSubstring: "nil list schema",
	}, {
		desc: "zero length path",
		in: &tpb.SubscribeTest{
			Args: &tpb.SubscribeTest_HasKeys{
				&tpb.HasKeys{
					Path: &gpb.Path{},
				},
			},
		},
		wantErrSubstring: "zero length path specified in argument",
	}, {
		desc: "keys specified",
		in: &tpb.SubscribeTest{
			Args: &tpb.SubscribeTest_HasKeys{
				&tpb.HasKeys{
					Path: &gpb.Path{
						Elem: []*gpb.PathElem{{
							Name: "test",
							Key:  map[string]string{"key": "val"},
						}},
					},
				},
			},
		},
		wantErrSubstring: "invalid path with keys specified in argument",
	}, {
		desc: "single item specified",
		in: &tpb.SubscribeTest{
			Args: &tpb.SubscribeTest_HasKeys{
				&tpb.HasKeys{
					Path: &gpb.Path{
						Elem: []*gpb.PathElem{{
							Name: "list",
						}},
					},
					Item: []*tpb.HasKeys_Item{{
						Key: map[string]string{
							"name": "value_one",
						},
					}},
				},
			},
		},
		want: []*gpb.Path{{
			Elem: []*gpb.PathElem{{
				Name: "list",
				Key:  map[string]string{"name": "value_one"},
			}},
		}},
	}, {
		desc: "multiple items specified",
		in: &tpb.SubscribeTest{
			Args: &tpb.SubscribeTest_HasKeys{
				&tpb.HasKeys{
					Path: &gpb.Path{
						Elem: []*gpb.PathElem{{
							Name: "list",
						}},
					},
					Item: []*tpb.HasKeys_Item{{
						Key: map[string]string{"name": "value_one"},
					}, {
						Key: map[string]string{"name": "value_two"},
					}},
				},
			},
		},
		want: []*gpb.Path{{
			Elem: []*gpb.PathElem{{
				Name: "list",
				Key:  map[string]string{"name": "value_one"},
			}},
		}, {
			Elem: []*gpb.PathElem{{
				Name: "list",
				Key:  map[string]string{"name": "value_two"},
			}},
		}},
	}, {
		desc: "multiple elements in base path",
		in: &tpb.SubscribeTest{
			Args: &tpb.SubscribeTest_HasKeys{
				&tpb.HasKeys{
					Path: &gpb.Path{
						Elem: []*gpb.PathElem{{
							Name: "container",
						}, {
							Name: "list",
						}},
					},
					Item: []*tpb.HasKeys_Item{{
						Key: map[string]string{"name": "v1"},
					}},
				},
			},
		},
		want: []*gpb.Path{{
			Elem: []*gpb.PathElem{{
				Name: "container",
			}, {
				Name: "list",
				Key:  map[string]string{"name": "v1"},
			}},
		}},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := completePaths(tt.in)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("did not get expected paths, got: %v, want: %v", got, tt.want)
			}
		})
	}
}

type Root struct {
	SingleKeyList map[string]*ListChild   `path:"single-key-list"`
	MultiKeyList  map[MultiKey]*ListChild `path:"multi-key-list"`
}

func (*Root) IsYANGGoStruct() {}

type MultiKey struct {
	String  string `path:"string"`
	Integer int32  `path:"integer"`
}

type ListChild struct {
	String  *string `path:"string"`
	Integer *int32  `path:"integer"`
}

func (l *ListChild) ΛListKeyMap() (map[string]interface{}, error) {
	return map[string]interface{}{
		"string":  *l.String,
		"integer": *l.Integer,
	}, nil
}

func (*ListChild) IsYANGGoStruct() {}

func TestCheckKeys(t *testing.T) {
	rootSchema := &yang.Entry{
		Name: "",
		Kind: yang.DirectoryEntry,
		Dir: map[string]*yang.Entry{
			"single-key-list": {
				Name:     "single-key-list",
				Key:      "string",
				ListAttr: &yang.ListAttr{},
				Dir: map[string]*yang.Entry{
					"string": {
						Name: "string",
						Kind: yang.LeafEntry,
						Type: &yang.YangType{Kind: yang.Ystring},
					},
					"integer": {
						Name: "integer",
						Kind: yang.LeafEntry,
						Type: &yang.YangType{Kind: yang.Yint32},
					},
				},
			},
			"multi-key-list": {
				Name:     "multi-key-list",
				Key:      "string integer",
				ListAttr: &yang.ListAttr{},
				Dir: map[string]*yang.Entry{
					"string": {
						Name: "string",
						Kind: yang.LeafEntry,
						Type: &yang.YangType{Kind: yang.Ystring},
					},
					"integer": {
						Name: "integer",
						Kind: yang.LeafEntry,
						Type: &yang.YangType{Kind: yang.Yint32},
					},
				},
			},
		},
	}

	tests := []struct {
		desc       string
		inSchema   *yang.Entry
		inDataTree ygot.GoStruct
		inPaths    []*gpb.Path
		wantErr    bool
	}{{
		desc:     "one item in single key list",
		inSchema: rootSchema,
		inDataTree: &Root{
			SingleKeyList: map[string]*ListChild{
				"foo": {String: ygot.String("foo")},
			},
		},
		inPaths: []*gpb.Path{
			path("/single-key-list[string=foo]"),
		},
	}, {
		desc:     "one item in multi key list",
		inSchema: rootSchema,
		inDataTree: &Root{
			MultiKeyList: map[MultiKey]*ListChild{
				MultiKey{String: "foo", Integer: 42}: {String: ygot.String("foo"), Integer: ygot.Int32(42)},
			},
		},
		inPaths: []*gpb.Path{
			path("/multi-key-list[string=foo][integer=42]"),
		},
	}, {
		desc:     "two items in single key list",
		inSchema: rootSchema,
		inDataTree: &Root{
			SingleKeyList: map[string]*ListChild{
				"foo": {String: ygot.String("foo")},
				"bar": {String: ygot.String("bar")},
			},
		},
		inPaths: []*gpb.Path{
			path("/single-key-list[string=foo]"),
			path("/single-key-list[string=bar]"),
		},
	}, {
		desc:     "two items in multi key list",
		inSchema: rootSchema,
		inDataTree: &Root{
			MultiKeyList: map[MultiKey]*ListChild{
				{String: "foo", Integer: 42}: {String: ygot.String("foo"), Integer: ygot.Int32(42)},
				{String: "bar", Integer: 84}: {String: ygot.String("bar"), Integer: ygot.Int32(84)},
			},
		},
		inPaths: []*gpb.Path{
			path("/multi-key-list[string=foo][integer=42]"),
			path("/multi-key-list[string=bar][integer=84]"),
		},
	}, {
		desc:     "non-existent path in single key list",
		inSchema: rootSchema,
		inDataTree: &Root{
			SingleKeyList: map[string]*ListChild{},
		},
		inPaths: []*gpb.Path{
			path("/single-key-list[string=nope]"),
		},
		wantErr: true,
	}, {
		desc:     "non-existent path in a multi key list",
		inSchema: rootSchema,
		inDataTree: &Root{
			MultiKeyList: map[MultiKey]*ListChild{},
		},
		inPaths: []*gpb.Path{
			path("/multi-key-list[string=nope][integer=-1]"),
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ts := &test{
				dataTree: tt.inDataTree,
				schema:   tt.inSchema,
				paths:    tt.inPaths,
			}

			if err := ts.Check(); (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error, got: %v, wantErr? %v", err, tt.wantErr)
			}
		})
	}
}

func TestIntegrationWithSchema(t *testing.T) {
	tests := []struct {
		desc                 string
		inConfig             *tpb.Test
		inSubscribeResponses []*gpb.SubscribeResponse
		wantErr              bool
	}{{
		desc: "interfaces exist",
		inConfig: &tpb.Test{
			Schema: openconfig.Key,
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_HasKeys{
						&tpb.HasKeys{
							Path: path("/interfaces/interface"),
							Item: []*tpb.HasKeys_Item{
								{Key: map[string]string{"name": "eth0"}},
								{Key: map[string]string{"name": "eth42"}},
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti("/interfaces", "/interface[name=eth0]/state/oper-status"),
			noti("/interfaces", "/interface[name=eth42]/state/oper-status"),
		},
	}, {
		desc: "interfaces do not exist",
		inConfig: &tpb.Test{
			Schema: openconfig.Key,
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_HasKeys{
						&tpb.HasKeys{
							Path: path("/interfaces/interface"),
							Item: []*tpb.HasKeys_Item{
								{Key: map[string]string{"name": "eth0"}},
								{Key: map[string]string{"name": "eth42"}},
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti("/interfaces", "/interface[name=eth0]/state/oper-status"),
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ts, err := newTest(tt.inConfig)
			if err != nil {
				t.Fatalf("invalid configuration supplied: %v", err)
			}

			for _, sr := range tt.inSubscribeResponses {
				if _, err := ts.Process(sr); err != nil {
					t.Fatalf("cannot process SubscribeResponse %s, got: %v", proto.MarshalTextString(sr), err)
				}
			}

			if err := ts.Check(); (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error status, got: %v, wantErr? %v", err, tt.wantErr)
			}
		})
	}
}

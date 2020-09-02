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

package valuevalidation

import (
	"testing"

	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmitest/schemas/openconfig/register"
	"github.com/openconfig/ygot/ygot"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

func mustPath(p string) *gpb.Path {
	path, err := ygot.StringToStructuredPath(p)
	if err != nil {
		panic(err)
	}
	return path
}

func noti(prefixPath string, updatePath string, v *gpb.TypedValue) *gpb.SubscribeResponse {
	return &gpb.SubscribeResponse{
		Response: &gpb.SubscribeResponse_Update{
			Update: &gpb.Notification{
				Prefix: mustPath(prefixPath),
				Update: []*gpb.Update{
					&gpb.Update{
						Path: mustPath(updatePath),
						Val:  v,
					},
				},
			},
		},
	}
}

func TestValueValidation(t *testing.T) {
	tests := []struct {
		desc    string
		upd     *gpb.SubscribeResponse
		wantErr string
	}{
		{
			desc: "success setting interface admin-status state",
			upd: noti(
				"interfaces",
				"interface[name=arbitrary_key]/state/admin-status",
				&gpb.TypedValue{Value: &gpb.TypedValue_StringVal{StringVal: "TESTING"}},
			),
		},
		{
			desc: "fail setting interface admin-status state",
			upd: noti(
				"interfaces",
				"interface[name=arbitrary_key]/state/admin-status",
				&gpb.TypedValue{Value: &gpb.TypedValue_StringVal{StringVal: "BAD-ENUM"}},
			),
			wantErr: "BAD-ENUM is not a valid value for enum field AdminStatus",
		},
		{
			desc: "fail unmarshallling container node which belongs to another container",
			upd: noti(
				"interfaces",
				"",
				&gpb.TypedValue{Value: &gpb.TypedValue_StringVal{StringVal: "TESTING"}},
			),
			wantErr: `path elem:<name:"interfaces" >  points to a node with non-leaf schema`,
		},
		{
			desc: "fail unmarshallling container node which belongs to a keyed list",
			upd: noti(
				"interfaces",
				"interface[name=arbitrary_key]",
				&gpb.TypedValue{Value: &gpb.TypedValue_StringVal{StringVal: "TESTING"}},
			),
			wantErr: `path elem:<name:"interfaces" > elem:<name:"interface" key:<key:"name" value:"arbitrary_key" > >  points to a node with non-leaf schema`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			gt, err := newTest(&tpb.Test{Schema: openconfig.Key})
			if err != nil {
				t.Fatalf("newTest failed: %v", err)
			}

			_, err = gt.Process(tt.upd)
			if diff := errdiff.Substring(err, tt.wantErr); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}
		})
	}
}

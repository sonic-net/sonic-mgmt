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

package pathvalidation

import (
	"testing"

	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmitest/schemas/openconfig/register"
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

func TestPathValidation(t *testing.T) {
	tests := []struct {
		inDesc           string
		inPrefixPath     string
		inUpdatePath     string
		wantErrSubstring string
	}{
		{
			inDesc:       "success path points to a leaf node",
			inPrefixPath: "interfaces",
			inUpdatePath: "interface[name=arbitrary_key]/state/admin-status",
		},
		{
			inDesc:           "fail path doesn't match due to partial defined element at the end",
			inPrefixPath:     "interfaces",
			inUpdatePath:     "interface[name=arbitrary_key]/state",
			wantErrSubstring: `path doesn't point to leaf node, *gostructs.OpenconfigInterfaces_Interfaces_Interface_State`,
		},
		{
			inDesc:           "fail path doesn't match due to incorrect key name for the interface",
			inPrefixPath:     "interfaces",
			inUpdatePath:     "interface[INCORRECT=arbitrary_key]/state",
			wantErrSubstring: "missing name key in map[INCORRECT:arbitrary_key]",
		},
		{
			inDesc:           "fail path points to a non-leaf node",
			inPrefixPath:     "network-instances",
			inUpdatePath:     "network-instance[name=arbitrary_key]",
			wantErrSubstring: "path doesn't point to leaf node",
		},
		{
			inDesc:           "fail path points to a non-leaf node",
			inPrefixPath:     "network-instances",
			inUpdatePath:     "network-instance[name=arbitrary_key]/protocols/protocol[name=arbitrary_name][identifier=DIRECTLY_CONNECTED]",
			wantErrSubstring: "path doesn't point to leaf node",
		},
		{
			inDesc:           "fail path uses a struct key type with incorrect enum",
			inPrefixPath:     "network-instances",
			inUpdatePath:     "network-instance[name=arbitrary_key]/protocols/protocol[name=arbitrary_name][identifier=INCORRECT_ENUM]",
			wantErrSubstring: "no enum matching with INCORRECT_ENUM",
		},
		{
			inDesc:       "success path points to a leaf node",
			inPrefixPath: "network-instances",
			inUpdatePath: "network-instance[name=arbitrary_key]/protocols/protocol[name=arbitrary_name][identifier=DIRECTLY_CONNECTED]/config/enabled",
		},
		{
			inDesc:       "success with optical device channel",
			inUpdatePath: "/terminal-device/logical-channels/channel[index=3100]/state/rate-class",
		},
		{
			inDesc:       "success with component property",
			inUpdatePath: "/components/component[name=AARDVARK]/properties/property[name=SALAMANDER]/state/value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.inDesc, func(t *testing.T) {
			subscribeTest, err := newTest(&tpb.Test{Schema: openconfig.Key})
			if err != nil {
				t.Fatalf("got %v", err)
			}
			_, err = subscribeTest.Process(noti(tt.inPrefixPath, tt.inUpdatePath))
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("diff: %v", diff)
			}
		})
	}
}

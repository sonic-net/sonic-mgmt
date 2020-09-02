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
package resolver

import (
	"testing"

	"github.com/openconfig/gnmi/errdiff"
)

var resetFunc = func() { rs = map[string]Resolver{} }

func TestGet(t *testing.T) {
	defer resetFunc()

	rs["arbitrary"] = nil
	rs[""] = nil

	tests := []struct {
		desc     string
		resolver string
		wantErr  string
	}{
		{
			desc: "retrieving empty resolver",
		},
		{
			desc:     "retrieving arbitrary resolver",
			resolver: "arbitrary",
		},
		{
			desc:     "retrieving unknown resolver",
			resolver: "unknown",
			wantErr:  "key doesn't exist",
		},
	}

	for _, tt := range tests {
		_, err := Get(tt.resolver)
		if diff := errdiff.Substring(err, tt.wantErr); diff != "" {
			t.Errorf("%v; Get(%q): %v", tt.desc, tt.resolver, diff)
		}
		if err != nil {
			continue
		}
	}
}

func TestSet(t *testing.T) {
	defer resetFunc()

	firstResolver := "first"
	if err := Set(firstResolver, nil); err != nil {
		t.Fatalf("got %v, want err nil", err)
	}

	if err := Set(firstResolver, nil); err == nil {
		t.Fatal("got err nil, want err")
	}
}
